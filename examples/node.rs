#![feature(generators, genertor_trait, use_extern_macros)]

extern crate actix;
extern crate futures_await as futures;
extern crate sonm;

use std::error::Error;
use std::fs::File;

use futures::prelude::{async, await, Future};
use sonm::{Account, Node};

#[async]
fn exec() -> Result<(), Box<dyn Error + 'static>> {
    let file = File::open("/Users/esafronov/.sonm/default/83a68c0aeaca382fc42122f125cbdc64d4b43fdd")?;
    let account = Account::from_rd(file).unwrap();
    let secret = account.decrypt("pidor").unwrap();
    println!("Read secret");
    let node = Node::new(secret);
    let balance = await!(node.balance()).unwrap();
    println!("Response: {}", balance.side_snm());

    actix::System::current().stop();

    Ok(())
}

fn main() -> Result<(), Box<Error>> {
    actix::run(|| exec().map_err(|_| ()).and_then(|_| { Ok(()) }));
    Ok(())
}
