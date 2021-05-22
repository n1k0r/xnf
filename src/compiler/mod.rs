use crate::lang::{self, filter::*, tokens::*};

use inkwell::{
    basic_block::BasicBlock,
    builder::Builder,
    context::Context,
    module::Module,
    targets::{CodeModel, InitializationConfig as InitConfig, Target, TargetTriple},
    values::{FunctionValue, IntValue, PointerValue},
    AddressSpace as AddrSpace, IntPredicate,
};

use std::path::PathBuf;

pub struct FilterObject {
    pub path: PathBuf,
    pub ir: String,
}

#[derive(Debug)]
pub enum CompileError {
    TargetUnavailable,
    ObjSaveError(String),
    TypeNotImplemented(Type),
    FieldType { field: String, proto: String },
    FieldSize { field: String, proto: String },
    FieldOffset { field: String, proto: String },
    CmpOpNotImplemented(CmpOp),
}

#[allow(dead_code)]
enum ActionCode {
    Drop = 1,
    Pass = 2,
}

const ETH_LEN: u64 = 14;
const ETHERTYPE_OFFSET: u64 = 12;

pub fn compile(filter: &lang::Filter) -> Result<FilterObject, CompileError> {
    let ctx = Context::create();
    let module = build_module(filter, &ctx)?;

    let path = save_obj(&module)?;
    let ir = module.print_to_string().to_string();

    Ok(FilterObject { path, ir })
}

#[allow(dead_code)]
struct FilterBuildEnv<'a, 'f> {
    filter: &'f lang::Filter,

    ctx: &'a Context,
    builder: &'a Builder<'a>,

    fn_main: &'a FunctionValue<'a>,
    pass: &'a BasicBlock<'a>,
    drop: &'a BasicBlock<'a>,
    data: &'a IntValue<'a>,
    data_end: &'a IntValue<'a>,

    offset: u64,
}

fn build_module<'a>(filter: &lang::Filter, ctx: &'a Context) -> Result<Module<'a>, CompileError> {
    let module = ctx.create_module("");

    let fn_main_type = ctx.i32_type().fn_type(
        &[
            ctx.i32_type()
                .ptr_type(AddrSpace::Generic)
                .into()
        ],
        false
    );
    let fn_main = module.add_function("main", fn_main_type, None);
    fn_main.as_global_value().set_section("xdp");
    let xdpctx = fn_main.get_nth_param(0).unwrap().into_pointer_value();

    let builder = ctx.create_builder();

    let init = ctx.append_basic_block(fn_main, "init");

    let action_pass = ctx.append_basic_block(fn_main, "pass");
    builder.position_at_end(action_pass);
    let result = ctx.i32_type().const_int(ActionCode::Pass as u64, false);
    builder.build_return(Some(&result));

    let action_drop = ctx.append_basic_block(fn_main, "drop");
    builder.position_at_end(action_drop);
    let result = ctx.i32_type().const_int(ActionCode::Drop as u64, false);
    builder.build_return(Some(&result));

    let start = ctx.append_basic_block(fn_main, "start");

    builder.position_at_end(init);
    builder.build_unconditional_branch(start);

    builder.position_at_end(start);
    let data = builder.build_load(xdpctx, "data_32").into_int_value();
    let data = builder.build_int_z_extend(data, ctx.i64_type(), "data");
    let data_end_offset = ctx.i64_type().const_int(1, false);
    let data_end_pos_ptr = unsafe { builder.build_gep(xdpctx, &[data_end_offset], "data_end_pos_ptr") };
    let data_end = builder.build_load(data_end_pos_ptr, "data_end_32").into_int_value();
    let data_end = builder.build_int_z_extend(data_end, ctx.i64_type(), "data_end");

    let mut env = FilterBuildEnv {
        filter: filter,
        ctx,
        builder: &builder,
        fn_main: &fn_main,
        pass: &action_pass,
        drop: &action_drop,
        data: &data,
        data_end: &data_end,
        offset: 0,
    };

    let eth = ctx.append_basic_block(fn_main, "eth");

    build_mem_check(&env, ETH_LEN, eth, action_pass);

    builder.position_at_end(eth);
    let eth_ptr = builder.build_int_to_ptr(data, ctx.i16_type().ptr_type(AddrSpace::Generic), "eth_ptr");
    let ethertype_offset = ctx.i32_type().const_int(ETHERTYPE_OFFSET / 2, false);
    let ethertype_ptr = unsafe { builder.build_gep(eth_ptr, &[ethertype_offset], "ethertype_ptr") };
    let ethertype = builder.build_load(ethertype_ptr, "ethertype").into_int_value();

    let rules = ctx.append_basic_block(fn_main, "rules");
    builder.build_unconditional_branch(rules);
    builder.position_at_end(rules);

    for rule in filter.rules() {
        build_rule(&mut env, rule, &ethertype)?;
    }

    builder.build_unconditional_branch(action_pass);

    Ok(module)
}

fn build_rule<'a>(env: &'a mut FilterBuildEnv, rule: &lang::Rule, ethertype: &'a IntValue<'a>) -> Result<(), CompileError> {
    let fail = env.ctx.append_basic_block(*env.fn_main, "rule_fail");

    if let Some(Constant::Number(value)) = rule.ethertype {
        let value = (value as u16).to_be() as u64;
        let rule_ethertype = env.ctx.i32_type().const_int(value, false);
        let cmp_proto = env.builder.build_int_compare(inkwell::IntPredicate::EQ, *ethertype, rule_ethertype, "cmp_ethertype");

        let equal = env.ctx.append_basic_block(*env.fn_main, "equal");
        env.builder.build_conditional_branch(cmp_proto, equal, fail);
        env.builder.position_at_end(equal);
    }

    env.offset = ETH_LEN;

    for test in rule.tests.iter() {
        build_test_proto(env, test, fail)?;
    }

    let action = match rule.action {
        Action::Pass => env.pass,
        Action::Drop => env.drop,
        _ => unreachable!(),
    };
    env.builder.build_unconditional_branch(*action);

    env.builder.position_at_end(fail);

    Ok(())
}

fn build_test_proto<'a>(env: &'a mut FilterBuildEnv, prototest: &ProtoTest, fail: BasicBlock) -> Result<(), CompileError> {
    let proto = env.filter.protocols().iter().find(
        |p| p.name == prototest.protocol
    ).unwrap();
    let bytes = (proto.size / 8) as u64;

    let fit = env.ctx.append_basic_block(*env.fn_main, "proto_fits");
    let ptr = build_mem_check(env, bytes, fit, fail);
    env.builder.position_at_end(fit);

    for field in prototest.tests.iter() {
        build_test_field(env, field, proto, ptr, fail)?;
    }

    env.offset += bytes;

    Ok(())
}

fn build_test_field<'a>(env: &'a FilterBuildEnv, fieldtest: &FieldTest, proto: &Protocol, ptr: PointerValue, fail: BasicBlock) -> Result<(), CompileError> {
    let field = proto.fields.iter().find(|f| f.name == fieldtest.field).unwrap();

    match &field.kind {
        Type::UInt => build_test_field_num(env, fieldtest, proto, field, ptr, fail)?,
        Type::Addr4 => build_test_field_addr4(env, fieldtest, proto, field, ptr, fail)?,
        Type::Addr6 => build_test_field_addr6(env, fieldtest, proto, field, ptr, fail)?,
        kind => return Err(CompileError::TypeNotImplemented(kind.clone())),
    }

    Ok(())
}

fn build_test_field_addr4<'a>(env: &'a FilterBuildEnv, fieldtest: &FieldTest, proto: &Protocol, field: &Field, ptr: PointerValue, fail: BasicBlock) -> Result<(), CompileError> {
    if field.size_bits != 32 {
        return Err(CompileError::FieldSize {
            field: field.name.clone(),
            proto: proto.name.clone(),
        });
    }

    if field.offset_bits % 8 != 0 {
        return Err(CompileError::FieldOffset {
            field: field.name.clone(),
            proto: proto.name.clone(),
        });
    }

    let (addr, subnet) = if let Constant::Addr4(addr, subnet) = fieldtest.constant {
        (addr, subnet as u32)
    } else {
        return Err(CompileError::FieldType {
            field: field.name.clone(),
            proto: proto.name.clone(),
        });
    };

    let num_addr = u32::from(addr);
    let mask = (0xFFFFFFFF as u32) << (32 - subnet);
    let num_addr = (num_addr & mask).to_be();

    let offset_bytes = (field.offset_bits / 8) as u64;
    let offset = env.ctx.i32_type().const_int(offset_bytes, false);
    let ptr = unsafe { env.builder.build_gep(ptr, &[offset], "") };
    let ptr = env.builder.build_pointer_cast(ptr, env.ctx.i32_type().ptr_type(AddrSpace::Generic), "");
    let value = env.builder.build_load(ptr, "").into_int_value();
    let const_mask = env.ctx.i32_type().const_int(mask.to_be() as u64, false);
    let value = env.builder.build_and(value, const_mask, "");

    let addr_const = env.ctx.i32_type().const_int(num_addr as u64, false);
    let cmp = env.builder.build_int_compare(IntPredicate::EQ, value, addr_const, "");

    let equal = env.ctx.append_basic_block(*env.fn_main, "");
    env.builder.build_conditional_branch(cmp, equal, fail);
    env.builder.position_at_end(equal);

    Ok(())
}

fn build_test_field_addr6<'a>(env: &'a FilterBuildEnv, fieldtest: &FieldTest, proto: &Protocol, field: &Field, ptr: PointerValue, fail: BasicBlock) -> Result<(), CompileError> {
    if field.size_bits != 128 {
        return Err(CompileError::FieldSize {
            field: field.name.clone(),
            proto: proto.name.clone(),
        });
    }

    if field.offset_bits % 8 != 0 {
        return Err(CompileError::FieldOffset {
            field: field.name.clone(),
            proto: proto.name.clone(),
        });
    }

    let (addr, subnet) = if let Constant::Addr6(addr, subnet) = fieldtest.constant {
        (addr, subnet as u32)
    } else {
        return Err(CompileError::FieldType {
            field: field.name.clone(),
            proto: proto.name.clone(),
        });
    };

    let num_addr = u128::from(addr);
    let mask = u128::max_value() << (128 - subnet);
    let num_addr = (num_addr & mask).to_be();
    let mask = mask.to_be();

    let offset_bytes = (field.offset_bits / 8) as u64;
    let offset = env.ctx.i32_type().const_int(offset_bytes, false);
    let ptr = unsafe { env.builder.build_gep(ptr, &[offset], "") };
    let ptr = env.builder.build_pointer_cast(ptr, env.ctx.i128_type().ptr_type(AddrSpace::Generic), "");
    let value = env.builder.build_load(ptr, "").into_int_value();
    let const_mask = env.ctx.i128_type().const_int_arbitrary_precision(&[mask as u64, (mask >> 64) as u64]);
    let value = env.builder.build_and(value, const_mask, "");

    let addr_const = env.ctx.i128_type().const_int_arbitrary_precision(&[num_addr as u64, (num_addr >> 64) as u64]);
    let cmp = env.builder.build_int_compare(IntPredicate::EQ, value, addr_const, "");

    let equal = env.ctx.append_basic_block(*env.fn_main, "");
    env.builder.build_conditional_branch(cmp, equal, fail);
    env.builder.position_at_end(equal);

    Ok(())
}

fn build_test_field_num<'a>(env: &'a FilterBuildEnv, fieldtest: &FieldTest, proto: &Protocol, field: &Field, ptr: PointerValue, fail: BasicBlock) -> Result<(), CompileError> {
    if field.size_bits == 0 || field.size_bits > 64 {
        return Err(CompileError::FieldSize {
            field: field.name.clone(),
            proto: proto.name.clone(),
        });
    }

    if field.offset_bits % 8 != 0 {
        if field.size_bits >= 8 || field.size_bits >= 8 - field.offset_bits % 8 {
            return Err(CompileError::FieldSize {
                field: field.name.clone(),
                proto: proto.name.clone(),
            });
        }
    }

    let num;
    let value;

    let num_he = if let Constant::Number(num) = fieldtest.constant { num } else {
        return Err(CompileError::FieldType {
            field: field.name.clone(),
            proto: proto.name.clone(),
        });
    };
    if field.offset_bits % 8 == 0 {
        num = match field.size_bits {
            8 => num_he,
            16 => (num_he as u16).to_be() as u64,
            32 => (num_he as u32).to_be() as u64,
            _ => num_he.to_be(),
        };

        value = build_num_getter(env, field, ptr);
    } else {
        num = (num_he as u8) as u64;

        value = build_num_part_getter(env, field, ptr);
    }

    let op = match &fieldtest.op {
        CmpOp::Equal => IntPredicate::EQ,
        CmpOp::NotEqual => IntPredicate::NE,
        CmpOp::Greater => IntPredicate::UGT,
        CmpOp::GreaterOrEqual => IntPredicate::UGE,
        CmpOp::Lesser => IntPredicate::ULT,
        CmpOp::LesserOrEqual => IntPredicate::ULE,
        op => return Err(CompileError::CmpOpNotImplemented(op.clone())),
    };

    let num_const = env.ctx.i64_type().const_int(num, false);
    let cmp = env.builder.build_int_compare(op, value, num_const, "");

    let equal = env.ctx.append_basic_block(*env.fn_main, "");
    env.builder.build_conditional_branch(cmp, equal, fail);
    env.builder.position_at_end(equal);

    Ok(())
}

fn build_num_getter<'a>(env: &'a FilterBuildEnv, field: &Field, ptr: PointerValue<'a>) -> IntValue<'a> {
    let offset_bytes = (field.offset_bits / 8) as u64;
    let offset = env.ctx.i32_type().const_int(offset_bytes, false);
    let mut ptr = unsafe { env.builder.build_gep(ptr, &[offset], "") };

    ptr = match field.size_bits {
        8 => env.builder.build_pointer_cast(ptr, env.ctx.i8_type().ptr_type(AddrSpace::Generic), ""),
        16 => env.builder.build_pointer_cast(ptr, env.ctx.i16_type().ptr_type(AddrSpace::Generic), ""),
        64 => env.builder.build_pointer_cast(ptr, env.ctx.i64_type().ptr_type(AddrSpace::Generic), ""),
        _ => ptr,
    };

    let mut value = env.builder.build_load(ptr, "").into_int_value();
    if field.size_bits != 64 {
        value = env.builder.build_int_cast(value, env.ctx.i64_type(), "");
    }

    value
}

fn build_num_part_getter<'a>(env: &'a FilterBuildEnv, field: &Field, ptr: PointerValue<'a>) -> IntValue<'a> {
    let offset_bytes = (field.offset_bits / 8) as u64;
    let offset = env.ctx.i32_type().const_int(offset_bytes, false);
    let ptr = unsafe { env.builder.build_gep(ptr, &[offset], "") };

    let mut value = env.builder.build_load(ptr, "").into_int_value();
    let left_bits = field.offset_bits % 8;
    let right_bits = 8 - (field.offset_bits + field.size_bits) % 8;
    let mask_bits = (0xFF << (8 - left_bits)) as u8;
    let mask = env.ctx.i32_type().const_int(mask_bits as u64, false);
    let shift = env.ctx.i32_type().const_int(right_bits as u64, false);
    value = env.builder.build_and(value, mask, "");
    value = env.builder.build_right_shift(value, shift, false, "");
    value = env.builder.build_int_cast(value, env.ctx.i64_type(), "");

    value
}

fn build_mem_check<'a>(env: &'a FilterBuildEnv, offset: u64, then_block: BasicBlock, else_block: BasicBlock) -> PointerValue<'a> {
    let prev_offset = env.ctx.i64_type().const_int(env.offset, false);
    let pos = env.builder.build_int_add(*env.data, prev_offset, "");
    let ptr = env.builder.build_int_to_ptr(pos, env.ctx.i8_type().ptr_type(AddrSpace::Generic), "ptr");
    let offset = env.ctx.i32_type().const_int(offset, false);
    let end_ptr = unsafe { env.builder.build_gep(ptr, &[offset], "end_ptr") };
    let end = env.builder.build_ptr_to_int(end_ptr, env.ctx.i64_type(), "end");

    let check = env.builder.build_int_compare(inkwell::IntPredicate::ULE, end, *env.data_end, "check");
    env.builder.build_conditional_branch(check, then_block, else_block);

    ptr
}

fn save_obj(module: &Module) -> Result<PathBuf, CompileError> {
    let config = InitConfig {
        asm_parser: true,
        asm_printer: true,
        base: true,
        disassembler: true,
        info: true,
        machine_code: true,
    };
    Target::initialize_bpf(&config);

    let triple = TargetTriple::create("bpf");
    let machine = inkwell::targets::Target::from_triple(&triple).unwrap();
    let machine_target = match machine.create_target_machine(
        &triple,
        "",
        "",
        inkwell::OptimizationLevel::Default,
        inkwell::targets::RelocMode::Default,
        CodeModel::Default,
    ) {
        Some(machine) => machine,
        None => return Err(CompileError::TargetUnavailable),
    };

    let mut path = std::env::temp_dir();
    path.push("filter.o"); // TODO: generate name

    if let Err(error) = machine_target.write_to_file(
        &module,
        inkwell::targets::FileType::Object,
        &path
    ) {
        return Err(CompileError::ObjSaveError(error.to_string()));
    }

    Ok(path)
}
