use xnf::daemon::{Daemon, DaemonError, ListenerError};

fn main() {
    let mut daemon = match Daemon::new() {
        Ok(daemon) => daemon,
        Err(err) => {
            print_daemon_err(err);
            std::process::exit(1);
        }
    };

    println!("Daemon starting up");
    daemon.listen();
}

fn print_daemon_err(err: DaemonError) {
    match err {
        DaemonError::OpenListener(err) => print_listener_err(err),
    }
}

fn print_listener_err(err: ListenerError) {
    match err {
        ListenerError::ChannelBusy => eprintln!("Daemon is already running"),
        ListenerError::ReadPIDError(path, err) => eprintln!(
            "Cannot access pid file at {}: {}",
            path.to_str().unwrap(),
            err
        ),
        ListenerError::WritePIDError(path, err) => eprintln!(
            "Cannot write pid file at {}: {}",
            path.to_str().unwrap(),
            err
        ),
        ListenerError::CreateSockError(path, err) => eprintln!(
            "Cannot create socket at {}: {}",
            path.to_str().unwrap(),
            err
        ),
        ListenerError::RemoveSockError(path, err) => eprintln!(
            "Cannot clean old socket at {}: {}",
            path.to_str().unwrap(),
            err
        ),
    }
}
