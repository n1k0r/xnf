use std::{cmp::Ordering, net::{Ipv4Addr, Ipv6Addr}};

use crate::lang::{Const, CmpOp, Filter, Rule, RuleTest};

pub struct VerifiedRule<'a> {
    pub rule: &'a Rule,
    pub last: bool,
}

pub fn verify<'a>(filter: &'a Filter, test: &RuleTest) -> Vec<VerifiedRule<'a>> {
    let mut rules = vec![];

    let mut ifaces_done = vec![];
    for rule in filter.rules().iter() {
        if let Some(iface) = &rule.iface {
            if ifaces_done.contains(&iface) {
                continue;
            }
        }

        let cmp = test_covered(test, rule);
        if cmp == TestCmp::Diverges {
            continue;
        }

        rules.push(VerifiedRule {
            rule,
            last: cmp == TestCmp::Includes,
        });

        if cmp == TestCmp::Includes {
            if let Some(iface) = &rule.iface {
                ifaces_done.push(iface);
            } else {
                break;
            }
        }
    }

    rules
}

#[derive(PartialEq)]
enum TestCmp {
    Includes,
    Intersects,
    Diverges,
}

fn test_covered(test: &RuleTest, rule: &Rule) -> TestCmp {
    let rule_test = match &rule.test {
        Some(rule_test) => rule_test,
        None => return TestCmp::Includes,
    };

    if test.ethertype != rule_test.ethertype {
        return TestCmp::Diverges;
    }

    let mut intersects = false;

    let protos = test.tests.iter().zip(rule_test.tests.iter());
    for (test_proto, rule_proto) in protos {
        if test_proto.protocol != rule_proto.protocol {
            return TestCmp::Diverges;
        }

        for field in rule_proto.tests.iter() {
            let test_field = match test_proto.tests.iter().find(|f| f.field == field.field) {
                Some(field) => field,
                None => {
                    intersects = true;
                    continue;
                },
            };

            let both_ops_eq =  test_field.op == CmpOp::Equal && field.op == CmpOp::Equal;
            let cmp = match (&test_field.constant, &field.constant) {
                (Const::Number(a), Const::Number(b)) => cmp_num_range(&test_field.op, *a, &field.op, *b),
                (Const::Addr4(addr, prefix), Const::Addr4(range_addr, range_prefix)) if both_ops_eq =>
                    Some(cmp_addr4_range(*addr, *prefix, *range_addr, *range_prefix)),
                (Const::Addr6(addr, prefix), Const::Addr6(range_addr, range_prefix)) if both_ops_eq =>
                    Some(cmp_addr6_range(*addr, *prefix, *range_addr, *range_prefix)),
                _ => Some(TestCmp::Diverges),
            };

            match cmp {
                Some(TestCmp::Includes) => continue,
                Some(TestCmp::Intersects) => intersects = true,
                _ => return TestCmp::Diverges,
            }
        }
    }

    if rule_test.tests.len() > test.tests.len() {
        return TestCmp::Intersects;
    }

    match intersects {
        true => TestCmp::Intersects,
        false => TestCmp::Includes,
    }
}

fn cmp_num_range(op: &CmpOp, value: u64, range_op: &CmpOp, range_value: u64) -> Option<TestCmp> {
    fn conv_range(op: &CmpOp, value: u64) -> (CmpOp, u64) {
        match op {
            CmpOp::GreaterOrEqual => (CmpOp::Greater, value - 1),
            CmpOp::LesserOrEqual => (CmpOp::Lesser, value + 1),
            _ => (op.clone(), value),
        }
    }

    let (op, value) = conv_range(op, value);
    let (range_op, range_value) = conv_range(range_op, range_value);

    let cmp = value.cmp(&range_value);

    match op {
        CmpOp::Lesser => match range_op {
            CmpOp::Lesser => match cmp {
                Ordering::Less => Some(TestCmp::Includes),
                Ordering::Equal => Some(TestCmp::Includes),
                Ordering::Greater => Some(TestCmp::Intersects),
            },
            CmpOp::Equal | CmpOp::Greater => match cmp {
                Ordering::Less => Some(TestCmp::Diverges),
                Ordering::Equal => Some(TestCmp::Diverges),
                Ordering::Greater => Some(TestCmp::Intersects),
            },
            CmpOp::NotEqual => Some(TestCmp::Intersects),
            _ => None,
        },
        CmpOp::Equal => match range_op {
            CmpOp::Lesser => match cmp {
                Ordering::Less => Some(TestCmp::Includes),
                Ordering::Equal => Some(TestCmp::Diverges),
                Ordering::Greater => Some(TestCmp::Diverges),
            },
            CmpOp::Equal => match cmp {
                Ordering::Less => Some(TestCmp::Diverges),
                Ordering::Equal => Some(TestCmp::Includes),
                Ordering::Greater => Some(TestCmp::Diverges),
            },
            CmpOp::NotEqual => match cmp {
                Ordering::Less => Some(TestCmp::Includes),
                Ordering::Equal => Some(TestCmp::Diverges),
                Ordering::Greater => Some(TestCmp::Includes),
            },
            CmpOp::Greater => match cmp {
                Ordering::Less => Some(TestCmp::Diverges),
                Ordering::Equal => Some(TestCmp::Diverges),
                Ordering::Greater => Some(TestCmp::Includes),
            },
            _ => None,
        },
        CmpOp::NotEqual => match range_op {
            CmpOp::Lesser | CmpOp::Greater => Some(TestCmp::Intersects),
            CmpOp::Equal => match cmp {
                Ordering::Less => Some(TestCmp::Includes),
                Ordering::Equal => Some(TestCmp::Diverges),
                Ordering::Greater => Some(TestCmp::Includes),
            },
            CmpOp::NotEqual => match cmp {
                Ordering::Less => Some(TestCmp::Intersects),
                Ordering::Equal => Some(TestCmp::Includes),
                Ordering::Greater => Some(TestCmp::Intersects),
            },
            _ => None,
        },
        CmpOp::Greater => match range_op {
            CmpOp::Lesser | CmpOp::Equal => match cmp {
                Ordering::Less => Some(TestCmp::Intersects),
                Ordering::Equal => Some(TestCmp::Diverges),
                Ordering::Greater => Some(TestCmp::Diverges),
            },
            CmpOp::NotEqual => Some(TestCmp::Intersects),
            CmpOp::Greater => match cmp {
                Ordering::Less => Some(TestCmp::Intersects),
                Ordering::Equal => Some(TestCmp::Includes),
                Ordering::Greater => Some(TestCmp::Includes),
            },
            _ => None,
        },
        _ => None,
    }
}

fn cmp_addr4_range(addr: Ipv4Addr, prefix: usize, range_addr: Ipv4Addr, range_prefix: usize) -> TestCmp {
    fn conv_addr(addr: Ipv4Addr, prefix: usize) -> u32 {
        use std::mem::size_of;

        let bitsize = size_of::<u32>() * 8;
        let mask: u32 = if prefix == 0 { 0 } else {
            u32::MAX - ((1 << (bitsize - prefix)) - 1)
        };

        u32::from(addr) & mask
    }

    let min_prefix = prefix.min(range_prefix);
    let uaddr = conv_addr(addr, min_prefix);
    let range_uaddr = conv_addr(range_addr, min_prefix);

    if uaddr != range_uaddr {
        return TestCmp::Diverges;
    }

    if range_prefix > prefix {
        return TestCmp::Intersects;
    }

    return TestCmp::Includes;
}

fn cmp_addr6_range(addr: Ipv6Addr, prefix: usize, range_addr: Ipv6Addr, range_prefix: usize) -> TestCmp {
    fn conv_addr(addr: Ipv6Addr, prefix: usize) -> u128 {
        use std::mem::size_of;

        let bitsize = size_of::<u128>() * 8;
        let mask: u128 = if prefix == 0 { 0 } else {
            u128::MAX - ((1 << (bitsize - prefix)) - 1)
        };

        u128::from(addr) & mask
    }

    let min_prefix = prefix.min(range_prefix);
    let uaddr = conv_addr(addr, min_prefix);
    let range_uaddr = conv_addr(range_addr, min_prefix);

    if uaddr != range_uaddr {
        return TestCmp::Diverges;
    }

    if range_prefix > prefix {
        return TestCmp::Intersects;
    }

    return TestCmp::Includes;
}
