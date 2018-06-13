/*
    Copyright © 2016 Zetok Zalbavar <zexavexxe@gmail.com>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

//! Old **Tox State Format (TSF)**. *__Will be deprecated__ when something
//! better will become available.*

use std::default::Default;
#[cfg(test)]
use byteorder::{BigEndian, LittleEndian, WriteBytesExt};
#[cfg(test)]
use byteorder::ByteOrder;
use nom::{be_u16, le_u16, le_u8, le_u32, le_u64, rest};

use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::dht::packed_node::*;
use toxcore::toxid::{NoSpam, NOSPAMBYTES};

#[cfg(test)]
use quickcheck::*;

// TODO: add logging where it's missing

/// Length in bytes of request message.
// FIXME: move somewhere else
// TODO: rename
const REQUEST_MSG_LEN: usize = 1024;

/// Size in bytes of serialized [`PackedNode`](./struct.PackedNode.html) with
/// IPv4.
pub const PACKED_NODE_IPV4_SIZE: usize = PUBLICKEYBYTES + 7;
/// Size in bytes of serialized [`PackedNode`](./struct.PackedNode.html) with
/// IPv6.
pub const PACKED_NODE_IPV6_SIZE: usize = PUBLICKEYBYTES + 19;


// TODO: improve docs

/** Sections of the old state format.

https://zetok.github.io/tox-spec/#sections
*/
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SectionKind {
    /** Section for [`NoSpam`](../../toxid/struct.NoSpam.html), public and
    secret keys.

    https://zetok.github.io/tox-spec/#nospam-and-keys-0x01
    */
    NospamKeys = 0x01,
    /** Section for DHT-related data – [`DhtState`](./struct.DhtState.html).

    https://zetok.github.io/tox-spec/#dht-0x02
    */
    // TODO: rename to DhtState
    DHT =        0x02,
    /** Section for friends data. Contains list of [`Friends`]
    (./struct.Friends.html).

    https://zetok.github.io/tox-spec/#friends-0x03
    */
    Friends =    0x03,
    /** Section for own [`Name`](./struct.Name.html).

    https://zetok.github.io/tox-spec/#name-0x04
    */
    Name =       0x04,
    /** Section for own [`StatusMsg`](./struct.StatusMsg.html).

    https://zetok.github.io/tox-spec/#status-message-0x05
    */
    StatusMsg =  0x05,
    /** Section for own [`UserStatus`](./enum.UserStatus.html).

    https://zetok.github.io/tox-spec/#status-0x06
    */
    // TODO: rename to UserStatus
    Status =     0x06,
    /** Section for a list of [`TcpRelays`](./struct.TcpRelays.html).

    https://zetok.github.io/tox-spec/#tcp-relays-0x0a
    */
    TcpRelays =  0x0a,
    /** Section for a list of [`PathNodes`](./struct.PathNodes.html) for onion
    routing.

    https://zetok.github.io/tox-spec/#path-nodes-0x0b
    */
    PathNodes =  0x0b,
}

impl FromBytes for SectionKind {
    named!(from_bytes<SectionKind>, switch ! (le_u16,
        0x01 => value ! (SectionKind::NospamKeys) |
        0x02 => value ! (SectionKind::DHT) |
        0x03 => value ! (SectionKind::Friends) |
        0x04 => value ! (SectionKind::Name) |
        0x05 => value ! (SectionKind::StatusMsg) |
        0x06 => value ! (SectionKind::Status) |
        0x0a => value ! (SectionKind::TcpRelays) |
        0x0b => value ! (SectionKind::PathNodes)
    ));
}

/** Serialization into bytes

```
use self::tox::toxcore::binary_io::ToBytes;
use self::tox::toxcore::state_format::old::SectionKind;

assert_eq!(vec![1u8, 0],   SectionKind::NospamKeys .to_bytes());
assert_eq!(vec![2u8, 0],   SectionKind::DHT        .to_bytes());
assert_eq!(vec![3u8, 0],   SectionKind::Friends    .to_bytes());
assert_eq!(vec![4u8, 0],   SectionKind::Name       .to_bytes());
assert_eq!(vec![5u8, 0],   SectionKind::StatusMsg  .to_bytes());
assert_eq!(vec![6u8, 0],   SectionKind::Status     .to_bytes());
assert_eq!(vec![10u8, 0],  SectionKind::TcpRelays  .to_bytes());
assert_eq!(vec![11u8, 0],  SectionKind::PathNodes  .to_bytes());
```
*/
impl ToBytes for SectionKind {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u16!(0x00 << 8 | *self as u8)
        )
    }
}


/// Implement returning matching SectionKind for sections.
trait SectionKindMatch {
    /// Returns matching `SectionKind`.
    fn kind() -> SectionKind;
}

macro_rules! section_kind_for_section {
    ($($skind:ident, $sect:ident, $tname:ident),+) => ($(
        impl SectionKindMatch for $sect {
            fn kind() -> SectionKind { SectionKind::$skind }
        }

        #[test]
        fn $tname() {
            assert_eq!(SectionKind::$skind, $sect::kind());
        }
    )+)
}
section_kind_for_section!(
    NospamKeys, NospamKeys, nospam_keys_kind_test,
    DHT, DhtState, dht_state_kind_test,
    Friends, Friends, friends_kind_test,
    Name, Name, name_kind_test,
    StatusMsg, StatusMsg, status_msg_kind_test,
    Status, UserStatus, user_status_kind_test,
    TcpRelays, TcpRelays, tcp_relays_kind_test,
    PathNodes, PathNodes, path_nodes_kind_test
);


/** NoSpam and Keys section of the old state format.

https://zetok.github.io/tox-spec/#nospam-and-keys-0x01
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NospamKeys {
    /// Own `NoSpam`.
    pub nospam: NoSpam,
    /// Own `PublicKey`.
    pub pk: PublicKey,
    /// Own `SecretKey`.
    pub sk: SecretKey,
}

/// Number of bytes of serialized [`NospamKeys`](./struct.NospamKeys.html).
pub const NOSPAMKEYSBYTES: usize = NOSPAMBYTES + PUBLICKEYBYTES + SECRETKEYBYTES;


/// The `Default` implementation generates random `NospamKeys`.
impl Default for NospamKeys {
    fn default() -> Self {
        let nospam = NoSpam::default();
        let (pk, sk) = gen_keypair();
        NospamKeys {
            nospam: nospam,
            pk: pk,
            sk: sk
        }
    }
}

/** Provided that there's at least [`NOSPAMKEYSBYTES`]
(./constant.NOSPAMKEYSBYTES.html) de-serializing will not fail.

E.g.

```
use self::tox::toxcore::binary_io::FromBytes;
use self::tox::toxcore::crypto_core::{
        PublicKey,
        PUBLICKEYBYTES,
        SecretKey,
        SECRETKEYBYTES,
};
use self::tox::toxcore::state_format::old::{NospamKeys, NOSPAMKEYSBYTES};
use self::tox::toxcore::toxid::{NoSpam, NOSPAMBYTES};

let bytes = [0; NOSPAMKEYSBYTES];

let result = NospamKeys {
    nospam: NoSpam([0; NOSPAMBYTES]),
    pk: PublicKey([0; PUBLICKEYBYTES]),
    sk: SecretKey([0; SECRETKEYBYTES]),
};

assert_eq!(None, NospamKeys::from_bytes(&bytes[..NOSPAMKEYSBYTES - 1]));
assert_eq!(result, NospamKeys::from_bytes(&bytes)
                    .expect("Failed to parse NospamKeys!"));
```
*/
impl FromBytes for NospamKeys {
    named!(from_bytes<NospamKeys>, do_parse!(
        nospam: call!(NoSpam::from_bytes) >>
        pk: call!(PublicKey::from_bytes) >>
        sk: call!(SecretKey::from_bytes) >>
        (NospamKeys {
            nospam: nospam,
            pk: pk,
            sk: sk
        })
    ));
}

/** E.g.

```
use self::tox::toxcore::binary_io::{FromBytes, ToBytes};
use self::tox::toxcore::crypto_core::*;
use self::tox::toxcore::state_format::old::{NospamKeys, NOSPAMKEYSBYTES};
use self::tox::toxcore::toxid::{NoSpam, NOSPAMBYTES};

{ // with `0` keys
    let nk = NospamKeys {
        nospam: NoSpam([0; NOSPAMBYTES]),
        pk: PublicKey([0; PUBLICKEYBYTES]),
        sk: SecretKey([0; SECRETKEYBYTES]),
    };
    assert_eq!(nk.to_bytes(), [0; NOSPAMKEYSBYTES].to_vec());
}

{ // with random
    let mut to_compare = Vec::with_capacity(NOSPAMKEYSBYTES);

    let mut nospam_bytes = [0; NOSPAMBYTES];
    randombytes_into(&mut nospam_bytes);
    to_compare.extend_from_slice(&nospam_bytes);

    let mut pk_bytes = [0; PUBLICKEYBYTES];
    randombytes_into(&mut pk_bytes);
    to_compare.extend_from_slice(&pk_bytes);

    let mut sk_bytes = [0; SECRETKEYBYTES];
    randombytes_into(&mut sk_bytes);
    to_compare.extend_from_slice(&sk_bytes);

    let nk = NospamKeys {
        nospam: NoSpam(nospam_bytes),
        pk: PublicKey(pk_bytes),
        sk: SecretKey(sk_bytes),
    };

    assert_eq!(to_compare, nk.to_bytes());
}

{ // with de-serialized
    let (pk, sk) = gen_keypair();
    let nk = NospamKeys {
        nospam: NoSpam::new(),
        pk: pk,
        sk: sk,
    };

    assert_eq!(nk, NospamKeys::from_bytes(&nk.to_bytes()).unwrap());
}
```
*/
impl ToBytes for NospamKeys {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.nospam.0) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_slice!(self.sk.0)
        )
    }
}


/** DHT section of the old state format.

https://zetok.github.io/tox-spec/#dht-0x02

Default is empty, no Nodes.

```
# use std::default::Default;
# use tox::toxcore::state_format::old::DhtState;
# use tox::toxcore::dht::PackedNode;
assert_eq!(&[] as &[PackedNode], DhtState::default().0.as_slice());
```
*/
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DhtState(pub Vec<PackedNode>);

/// Minimal number of bytes [`DhtState`](./struct.DhtState.html) has.
///
/// Assumes that at least all the magic numbers are present.
pub const DHT_STATE_MIN_SIZE: usize = 12;

/// Special, magical beginning of DHT section in LE.
// TODO: change to &'static [u8]
const DHT_MAGICAL: u32 = 0x159_000d;

/** Special DHT section type encoded in LE.

    https://zetok.github.io/tox-spec/#dht-sections
*/
const DHT_SECTION_TYPE: u16 = 0x04;

/** Yet another magical number in DHT section that needs a check.

https://zetok.github.io/tox-spec/#dht-sections
*/
const DHT_2ND_MAGICAL: u16 = 0x11ce;

/** If successful, returns `DhtState` and length of the section in bytes.

> **Note:** An empty list of nodes can be returned!

If de-serialization failed, returns `None`.

Fails when:

* number of bytes is less than [`DHT_STATE_MIN_SIZE`]
  (./constant.DHT_STATE_MIN_SIZE.html)
* one of 3 magic numbers doesn't match
* encoded length of section + `DHT_STATE_MIN_SIZE` is bigger than all
  suppplied bytes

E.g. de-serialization with an empty list:

```
use self::tox::toxcore::binary_io::*;
use self::tox::toxcore::dht::*;
use self::tox::toxcore::state_format::old::*;

let serialized = vec![
        0x0d, 0x00, 0x59, 0x01,  // the first magic number
        0, 0, 0, 0,   // number of `PackedNode`
        0x04, 0,  // section magic number
        0xce, 0x11,  // another magic number
        // here would go `PackedNode`s, but since their length is `0`..
];

assert_eq!(DhtState(vec![]), DhtState::from_bytes(&serialized).unwrap());
```
*/
impl FromBytes for DhtState {
    named!(from_bytes<DhtState>, do_parse!(
        verify!(le_u32, |value| value == DHT_MAGICAL) >> // check whether beginning of the section matches DHT magic bytes
        nodes: le_u32 >>
        verify!(le_u16, |value| value == DHT_SECTION_TYPE) >> // check DHT section type
        verify!(le_u16, |value| value == DHT_2ND_MAGICAL) >> // check whether yet another magic number matches
        pns: flat_map!(take!(nodes as usize), many0!(PackedNode::from_bytes)) >>
        (DhtState(pns))
    ));
}

/** E.g. serialization of an empty list:

```
use self::tox::toxcore::binary_io::*;
use self::tox::toxcore::dht::*;
use self::tox::toxcore::state_format::old::*;

let result = vec![
        0x0d, 0x00, 0x59, 0x01,  // the first magic number
        0, 0, 0, 0,   // number of `PackedNode`
        0x04, 0,  // section magic number
        0xce, 0x11,  // another magic number
        // here would go `PackedNode`s, but since their length is `0`..
];

assert_eq!(result, DhtState(vec![]).to_bytes());
```
*/
impl ToBytes for DhtState {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u32!(DHT_MAGICAL as u32) >>
            gen_le_u32!(self.0.len() as u32) >>
            gen_le_u16!(DHT_SECTION_TYPE as u16) >>
            gen_le_u16!(DHT_2ND_MAGICAL as u16) >>
            gen_many_ref!(&self.0, |buf, node| PackedNode::to_bytes(node, buf))
        )
    }
}


/** Friend state status. Used by [`FriendState`](./struct.FriendState.html).

https://zetok.github.io/tox-spec/#friends-0x03

```
use self::tox::toxcore::state_format::old::FriendStatus;

assert_eq!(0u8, FriendStatus::NotFriend as u8);
assert_eq!(1u8, FriendStatus::Added     as u8);
assert_eq!(2u8, FriendStatus::FrSent    as u8);
assert_eq!(3u8, FriendStatus::Confirmed as u8);
assert_eq!(4u8, FriendStatus::Online    as u8);
```
*/
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FriendStatus {
    /// Not a friend. (When this can happen and what does it entail?)
    NotFriend   = 0,
    /// Friend was added.
    Added       = 1,
    /// Friend request was sent to the friend.
    FrSent      = 2,
    /// Friend confirmed.
    /// (Something like toxcore knowing that friend accepted FR?)
    Confirmed   = 3,
    /// Friend has come online.
    Online      = 4,
}

/** E.g.

```
use self::tox::toxcore::binary_io::*;
use self::tox::toxcore::state_format::old::*;

{ // ::NotFriend
    let bytes = [FriendStatus::NotFriend as u8];
    assert_eq!(FriendStatus::NotFriend,
        FriendStatus::from_bytes(&bytes)
            .expect("Failed to de-serialize FriendStatus::NotFriend!"));
}

{ // ::Added
    let bytes = [FriendStatus::Added as u8];
    assert_eq!(FriendStatus::Added,
        FriendStatus::from_bytes(&bytes)
            .expect("Failed to de-serialize FriendStatus::Added!"));
}

{ // ::FrSent
    let bytes = [FriendStatus::FrSent as u8];
    assert_eq!(FriendStatus::FrSent,
        FriendStatus::from_bytes(&bytes)
            .expect("Failed to de-serialize FriendStatus::FrSent!"));
}

{ // ::Confirmed
    let bytes = [FriendStatus::Confirmed as u8];
    assert_eq!(FriendStatus::Confirmed,
        FriendStatus::from_bytes(&bytes)
            .expect("Failed to de-serialize FriendStatus::Confirmed!"));
}

{ // ::Online
    let bytes = [FriendStatus::Online as u8];
    assert_eq!(FriendStatus::Online,
        FriendStatus::from_bytes(&bytes)
            .expect("Failed to de-serialize FriendStatus::Online!"));
}

{ // empty
    assert_eq!(None, FriendStatus::from_bytes(&[]));
    let debug = format!("{:?}", FriendStatus::from_bytes(&[]).unwrap_err());
    let err_msg = "Not enough bytes for FriendStatus.";
    assert!(debug.contains(err_msg));
}

// wrong
for i in 5..256 {
    let bytes = [i as u8];
    assert_eq!(None, FriendStatus::from_bytes(&bytes));
    let debug = format!("{:?}", FriendStatus::from_bytes(&bytes).unwrap_err());
    let err_msg = format!("Unknown FriendStatus: {}", i);
    assert!(debug.contains(&err_msg));
}
```
*/
impl FromBytes for FriendStatus {
    named!(from_bytes<FriendStatus>, switch!(le_u8,
        0 => value!(FriendStatus::NotFriend) |
        1 => value!(FriendStatus::Added) |
        2 => value!(FriendStatus::FrSent) |
        3 => value!(FriendStatus::Confirmed) |
        4 => value!(FriendStatus::Online)
    ));
}

/** User status. Used for both own & friend statuses.

https://zetok.github.io/tox-spec/#userstatus

```
# use self::tox::toxcore::state_format::old::UserStatus;
assert_eq!(UserStatus::Online, UserStatus::default());
```
*/
// FIXME: *move somewhere else* (messenger?)
// TODO: rename to `Status` ?
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserStatus {
    /// User is `Online`.
    Online = 0,
    /// User is `Away`.
    Away   = 1,
    /// User is `Busy`.
    Busy   = 2,
}

/// Returns `UserStatus::Online`.
impl Default for UserStatus {
    fn default() -> Self {
        UserStatus::Online
    }
}

impl FromBytes for UserStatus {
    named!(from_bytes<UserStatus>, switch!(le_u8,
        0 => value!(UserStatus::Online) |
        1 => value!(UserStatus::Away) |
        2 => value!(UserStatus::Busy)
    ));
}

impl ToBytes for UserStatus {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u8!(*self as u8)
        )
    }
}

/** Friend state format for a single friend, compatible with what C toxcore
does with on `GCC x86{,_x64}` platform.

Data that is supposed to be strings (friend request message, friend name,
friend status message) might, or might not even be a valid UTF-8. **Anything
using that data should validate whether it's actually correct UTF-8!**

*feel free to add compatibility to what broken C toxcore does on other
platforms*

https://zetok.github.io/tox-spec/#friends-0x03
*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriendState {
    status: FriendStatus,
    pk: PublicKey,
    /// Friend request message that is being sent to friend.
    fr_msg: Vec<u8>,
    /// Friend's name.
    name: Name,
    status_msg: StatusMsg,
    user_status: UserStatus,
    nospam: NoSpam,
    /// Time when friend was last seen online.
    last_seen: u64,
}

impl FriendState {
    /** Add a new friend via `PublicKey`.

    State assumes that friend request was sent and accepted.
    */
    pub fn new_from_pk(pk: &PublicKey) -> Self {
        FriendState {
            status: FriendStatus::Added,
            pk: *pk,
            fr_msg: Vec::new(),
            name: Name::default(),
            status_msg: StatusMsg::default(),
            user_status: UserStatus::default(),
            nospam: NoSpam([0; NOSPAMBYTES]),
            last_seen: 0,
        }
    }
}


/// Number of bytes of serialized [`FriendState`](./struct.FriendState.html).
pub const FRIENDSTATEBYTES: usize = 1      // "Status"
                                  + PUBLICKEYBYTES
/* actual size of FR message   */ + 2
/* Friend request message      */ + REQUEST_MSG_LEN
/* actual size of Name         */ + 2
/* Name                        */ + NAME_LEN
/* actual size of status msg   */ + 2
/* Status msg                  */ + STATUS_MSG_LEN
/* UserStatus                  */ + 1
/* only used for sending FR    */ + NOSPAMBYTES
/* last time seen              */ + 8;

impl FromBytes for FriendState {
    named!(from_bytes<FriendState>, do_parse!(
        status: call!(FriendStatus::from_bytes) >>
        pk: call!(PublicKey::from_bytes) >>
        fr_msg_len: be_u16 >>
//        verify!(fr_msg_len, |len| len <= REQUEST_MSG_LEN) >>
        fr_msg_bytes: take!(fr_msg_len) >>
        fr_msg: value!(fr_msg_bytes[..fr_msg_len as usize].to_vec()) >>
        name_len: be_u16 >>
//        verify!(name_len, |len| len <= NAME_LEN) >>
        name_bytes: take!(name_len) >>
        name: value!(Name(name_bytes[..name_len as usize].to_vec())) >>
        status_msg_len: be_u16 >>
//        verify!(status_msg_len, |len| len <= STATUS_MSG_LEN) >>
        status_msg_bytes: take!(status_msg_len) >>
        status_msg: value!(StatusMsg(status_msg_bytes[..status_msg_len as usize].to_vec())) >>
        user_status: call!(UserStatus::from_bytes) >>
        nospam: call!(NoSpam::from_bytes) >>
        last_seen: le_u64 >>
        (FriendState {
            status,
            pk,
            fr_msg,
            name,
            status_msg,
            user_status,
            nospam,
            last_seen,
        })
    ));
}

// TODO: write tests ↑
impl ToBytes for FriendState {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_le_u8!(self.status as u8) >>
            gen_slice!(self.pk.as_ref()) >>
            gen_be_u16!(self.fr_msg.len()) >>
            gen_slice!(self.fr_msg.as_slice()) >>
            gen_be_u16!(self.name.0.len()) >>
            gen_slice!(self.name.0.as_slice()) >>
            gen_be_u16!(self.status_msg.0.len()) >>
            gen_slice!(self.status_msg.0.as_slice()) >>
            gen_le_u8!(self.user_status as u8) >>
            gen_slice!(self.nospam.0) >>
            gen_le_u64!(self.last_seen)
        )
    }
}

#[cfg(test)]
impl Arbitrary for FriendStatus {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        match g.gen_range(0, 5) {
            0 => FriendStatus::NotFriend,
            1 => FriendStatus::Added,
            2 => FriendStatus::FrSent,
            3 => FriendStatus::Confirmed,
            4 => FriendStatus::Online,
            err => {
                debug!("System error: gen_range(0, 5): {:?}", err);
                FriendStatus::NotFriend
            }
        }
    }
}

#[cfg(test)]
impl Arbitrary for UserStatus {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        match g.gen_range(0, 3) {
            0 => UserStatus::Online,
            1 => UserStatus::Away,
            2 => UserStatus::Busy,
            err => {
                debug!("System error: gen_range(0, 3): {:?}", err);
                UserStatus::Online
            }
        }
    }
}

#[cfg(test)]
impl Arbitrary for Name {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let name_len = g.gen_range(0, NAME_LEN);
        let mut name_buf = [0u8; NAME_LEN];
        g.fill_bytes(&mut name_buf[..name_len]);
        Name(name_buf[..name_len].to_vec())
    }
}

#[cfg(test)]
impl Arbitrary for StatusMsg {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let msg_len = g.gen_range(0, STATUS_MSG_LEN);
        let mut msg_buf = [0u8; STATUS_MSG_LEN];
        g.fill_bytes(&mut msg_buf[..msg_len]);
        StatusMsg(msg_buf[..msg_len].to_vec())
    }
}

#[cfg(test)]
impl Arbitrary for DhtState {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let node_num = g.gen_range(0, 65);
        let nodes = (0..node_num).into_iter()
            .map(|_| PackedNode::arbitrary(g))
            .collect::<Vec<PackedNode>>();
        DhtState(nodes)
    }
}

#[cfg(test)]
impl Arbitrary for NoSpam {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let mut no_spam_buf = [0u8; NOSPAMBYTES];
        g.fill_bytes(&mut no_spam_buf);
        NoSpam(no_spam_buf)
    }
}

#[cfg(test)]
impl Arbitrary for NospamKeys {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let mut pk_bytes = [0; PUBLICKEYBYTES];
        g.fill_bytes(&mut pk_bytes);
        let pk = PublicKey(pk_bytes);

        let mut sk_bytes = [0; SECRETKEYBYTES];
        g.fill_bytes(&mut sk_bytes);
        let sk = SecretKey(sk_bytes);

        NospamKeys {
            nospam: NoSpam::arbitrary(g),
            pk,
            sk,
        }
    }
}

#[cfg(test)]
impl Arbitrary for FriendState {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        // friend's PublicKey
        let mut pk_bytes = [0; PUBLICKEYBYTES];
        g.fill_bytes(&mut pk_bytes);
        let pk = PublicKey(pk_bytes);

        // friend message and its length
        let mut fr_msg = [0; REQUEST_MSG_LEN];
        let fr_msg_len = g.gen_range(0, REQUEST_MSG_LEN);
        g.fill_bytes(&mut fr_msg[..fr_msg_len]);
        let fr_msg = fr_msg[..fr_msg_len].to_vec();

        // friend name and its length
        let mut fname = [0; NAME_LEN];
        let fname_len = g.gen_range(0, NAME_LEN);
        g.fill_bytes(&mut fname[..fname_len]);
        let fname = Name(fname[..fname_len].to_vec());

        // status message and its length
        let mut status_msg = [0; STATUS_MSG_LEN];
        let status_msg_len = g.gen_range(0, STATUS_MSG_LEN);
        g.fill_bytes(&mut status_msg[..status_msg_len]);
        let status_msg = StatusMsg(status_msg[..status_msg_len].to_vec());

        let mut ns_bytes = [0; NOSPAMBYTES];
        g.fill_bytes(&mut ns_bytes);
        let nospam = NoSpam(ns_bytes);

        FriendState {
            status: Arbitrary::arbitrary(g),
            pk: pk,
            fr_msg: fr_msg,
            name: fname,
            status_msg: status_msg,
            user_status: Arbitrary::arbitrary(g),
            nospam: nospam,
            last_seen: Arbitrary::arbitrary(g),
        }
    }
}


// TODO: replace every `Vec<FriendState>` with `Friends`
/** Wrapper struct for `Vec<FriendState>` to ease working with friend lists.
*/
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Friends(pub Vec<FriendState>);

impl Friends {

    /// `true` if there is a friend with given `PublicKey`, `false` otherwise.
    pub fn is_friend(&self, pk: &PublicKey) -> bool {
        self.0.iter().any(|fs| fs.pk == *pk)
    }

    /** Add [`FriendState`](./struct.FriendState.html) to the list of friends.

    If the friend was already in `Friends`, `false` is returned, `true`
    otherwise.
    */
    pub fn add_friend(&mut self, fs: FriendState) -> bool {
        if self.is_friend(&fs.pk) {
            return false
        }

        self.0.push(fs);
        true
    }
}

impl FromBytes for Friends {
    named!(from_bytes<Friends>, map!(many0!(FriendState::from_bytes), Friends));
}

impl ToBytes for Friends {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_many_ref!(&self.0, |buf, friend| FriendState::to_bytes(friend, buf))
        )
    }
}

impl ToBytes for Name {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.0.as_slice())
        )
    }
}

impl ToBytes for StatusMsg {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(self.0.as_slice())
        )
    }
}

#[cfg(test)]
impl Arbitrary for Friends {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        Friends(Arbitrary::arbitrary(g))
    }
}


macro_rules! impl_to_bytes_for_bytes_struct {
    ($name:ty, $tname:ident) => (
        #[test]
        fn $tname() {
            fn test_fn(s: $name) {
                let mut buf = [0; 512];
                assert_eq!(s.0, s.to_bytes((&mut buf, 0)).unwrap().0);
            }
            quickcheck(test_fn as fn($name));
        }
    )
}

// TODO: refactor `Name` and `StatusMsg` to implementation via via macro,
//       in a similar way to how sodiumoxide does implementation via macros

/** Own name, up to [`NAME_LEN`](./constant.NAME_LEN.html) bytes long.
*/
// TODO: move elsewhere from this module
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Name(pub Vec<u8>);

/// Length in bytes of name. ***Will be moved elsewhere.***
// FIXME: move somewhere else
pub const NAME_LEN: usize = 128;

impl Name {
    /** Create new `Name` from bytes in a slice. If there are more bytes than
    [`NAME_LEN`](./constant.NAME_LEN.html), use only `NAME_LEN` bytes.

    E.g.:

    ```
    use self::tox::toxcore::state_format::old::*;

    for n in 0..(NAME_LEN + 1) {
        let bytes = vec![0; n];
        assert_eq!(bytes, Name::new(&bytes).0);
    }

    for n in (NAME_LEN + 1)..(NAME_LEN + 20) {
        let bytes = vec![0; n];
        assert_eq!(&bytes[..NAME_LEN], Name::new(&bytes).0.as_slice());
    }
    ```
    */
    pub fn new(bytes: &[u8]) -> Self {
        if bytes.len() < NAME_LEN {
            Name(bytes.to_vec())
        } else {
            Name(bytes[..NAME_LEN].to_vec())
        }
    }
}

/** Produces up to [`NAME_LEN`](./constant.NAME_LEN.html) bytes long `Name`.
    Can't fail.
*/
impl FromBytes for Name {
    named!(from_bytes<Name>, map!(alt_complete!(take!(NAME_LEN) | rest), Name::new));
}

impl_to_bytes_for_bytes_struct!(Name, name_to_bytes_test);


/** Status message, up to [`STATUS_MSG_LEN`](./constant.STATUS_MSG_LEN.html)
bytes.

> ***Note: will be moved (and renamed?)***.
*/
// TODO: rename(?) & move from this module
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StatusMsg(pub Vec<u8>);

/// Length in bytes of friend's status message.
// FIXME: move somewhere else
pub const STATUS_MSG_LEN: usize = 1007;

impl StatusMsg {
    /** Create new `StatusMsg` from bytes in a slice. If there are more bytes
    than [`STATUS_MSG_LEN`](./constant.STATUS_MSG_LEN.html), use only
    `STATUS_MSG_LEN` bytes.

    E.g.:

    ```
    use self::tox::toxcore::state_format::old::*;

    for n in 0..(STATUS_MSG_LEN + 1) {
        let bytes = vec![0; n];
        assert_eq!(bytes, StatusMsg::new(&bytes).0);
    }

    for n in (STATUS_MSG_LEN + 1)..(STATUS_MSG_LEN + 20) {
        let bytes = vec![0; n];
        assert_eq!(&bytes[..STATUS_MSG_LEN],
                StatusMsg::new(&bytes).0.as_slice());
    }
    ```
    */
    pub fn new(bytes: &[u8]) -> Self {
        if bytes.len() < STATUS_MSG_LEN {
            StatusMsg(bytes.to_vec())
        } else {
            StatusMsg(bytes[..STATUS_MSG_LEN].to_vec())
        }
    }
}

#[cfg(test)]
macro_rules! impl_arb_for_pn {
    ($name:ident) => (
        impl Arbitrary for $name {
            fn arbitrary<G: Gen>(g: &mut G) -> Self {
                $name(Arbitrary::arbitrary(g))
            }
        }
    )
}

/** PublicKey from bytes. Returns `TestResult::discard()` if there are not
enough bytes.
*/
#[cfg(test)]
macro_rules! quick_pk_from_bytes {
    ($input:ident, $out:ident) => (
        if $input.len() < PUBLICKEYBYTES {
            return TestResult::discard()
        }

        let $out = PublicKey::from_slice(&$input[..PUBLICKEYBYTES])
            .expect("Failed to make PK from slice");
    )
}

/** Produces up to [`STATUS_MSG_LEN`](./constant.STATUS_MSG_LEN.html) bytes
long `StatusMsg`. Can't fail.
*/
impl FromBytes for StatusMsg {
    named!(from_bytes<StatusMsg>, map!(alt_complete!(take!(STATUS_MSG_LEN) | rest), StatusMsg::new));
}

impl_to_bytes_for_bytes_struct!(StatusMsg, status_msg_to_bytes_test);

macro_rules! nodes_list {
    ($($name:ident, $tname:ident),+) => ($(
        /// Contains list in `PackedNode` format.
        #[derive(Clone, Debug, Default, Eq, PartialEq)]
        pub struct $name(pub Vec<PackedNode>);

        impl FromBytes for $name {
            named!(from_bytes<$name>, map!(many0!(PackedNode::from_bytes), $name));
        }

        impl ToBytes for $name {
            fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
                do_gen!(buf,
                    gen_many_ref!(&self.0, |buf, node| PackedNode::to_bytes(node, buf))
                )
            }
        }

        #[cfg(test)]
        impl_arb_for_pn!($name);

        #[cfg(test)]
        #[test]
        // TODO: test also for failures? should be covered by other test, but..
        fn $tname() {
            fn with_pns(pns: Vec<PackedNode>) {
                let mut bytes = Vec::new();
                let mut buf = [0u8; 1024];
                for pn in &pns {
                    bytes.append(&mut pn.to_bytes((&mut buf, 0)).unwrap().0.to_vec());
                }
                {
                    let (r_bytes, p) = $name::from_bytes(&bytes).unwrap();

                    assert_eq!(p.0, pns);
                    assert_eq!(&[] as &[u8], r_bytes);
                }

                assert_eq!($name(pns).to_bytes((&mut buf, 0)).unwrap().0.to_vec(), bytes);
            }
            quickcheck(with_pns as fn(Vec<PackedNode>));

            // Default impl test
            assert_eq!(&[] as &[PackedNode], $name::default().0.as_slice());
        }
    )+)
}

nodes_list!(TcpRelays, tcp_relays_test,
            PathNodes, path_nodes_test);


/// Data for `Section`. Might, or might not contain valid data.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SectionData {
    kind: SectionKind,
    data: Vec<u8>,
}

/// Minimal length in bytes of an empty section. Any section that is not empty
/// should be bigger.
#[cfg(test)]
const SECTION_MIN_LEN: usize = 8;

/// According to https://zetok.github.io/tox-spec/#sections
const SECTION_MAGIC: &[u8; 2] = &[206, 1];

impl SectionData {

    /** Try to parse `SectionData`'s bytes into [`Section`]
    (./enum.Section.html).

    Fails if `SectionData` doesn't contain valid data.
    */
    // TODO: test failures?
    fn as_section(&self) -> IResult<&[u8], Section> {
        match self.kind {
            SectionKind::NospamKeys => NospamKeys::from_bytes(&self.data)
                .map(Section::NospamKeys),
            SectionKind::DHT => DhtState::from_bytes(&self.data)
                .map(Section::DHT),
            SectionKind::Friends => Friends::from_bytes(&self.data)
                .map(Section::Friends),
            SectionKind::Name => Name::from_bytes(&self.data)
                .map(Section::Name),
            SectionKind::StatusMsg => StatusMsg::from_bytes(&self.data)
                .map(Section::StatusMsg),
            SectionKind::Status => UserStatus::from_bytes(&self.data)
                .map(Section::Status),
            SectionKind::TcpRelays => TcpRelays::from_bytes(&self.data)
                .map(Section::TcpRelays),
            SectionKind::PathNodes => PathNodes::from_bytes(&self.data)
                .map(Section::PathNodes),
        }
    }

    /** Try to parse `SectionData`'s bytes into multiple [`Section`s]
    (./enum.Section.html).

    Fails if `SectionData` doesn't contain valid data.

    Can return empty `Vec<_>`.
    */
    // TODO: move under `Section` ?
    fn into_sect_mult(s: &[SectionData]) -> Vec<Section> {
        // TODO: don't return an empty Vec ?
        s.iter()
            .map(|sd| sd.as_section())
            .filter(|s| s.clone().to_result().is_ok())
            .map(|s| s.to_result().unwrap())
            .collect()
    }
}


impl FromBytes for SectionData {
    named!(from_bytes<SectionData>, do_parse!(
        data_len: le_u32 >>
        kind: call!(SectionKind::from_bytes) >>
        tag!(SECTION_MAGIC) >>
        data: take!(data_len) >>
        (SectionData { kind, data: data.to_vec() })
    ));
}

#[cfg(test)]
impl Arbitrary for SectionKind {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let mut range_val: u8 = 7;

        while range_val > 6 && range_val < 0x0a {
            range_val = g.gen_range(1, 0x0c);
        }

        match range_val {
            1 => SectionKind::NospamKeys,
            2 => SectionKind::DHT,
            3 => SectionKind::Friends,
            4 => SectionKind::Name,
            5 => SectionKind::StatusMsg,
            6 => SectionKind::Status,
            0x0a => SectionKind::TcpRelays,
            0x0b => SectionKind::PathNodes,
            _ => {
                debug!("system error: gen_range() error");
                SectionKind::NospamKeys
            },
        }
    }
}

#[cfg(test)]
impl Arbitrary for SectionData {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let mut range_val: u8 = 7;

        while range_val > 6 && range_val < 0x0a {
            range_val = g.gen_range(1, 0x0c);
        }

        let mut buf = [0u8; 2048];

        let data = match range_val {
            1 => NospamKeys::arbitrary(g).to_bytes((&mut buf, 0)).unwrap().0,
            2 => DhtState::arbitrary(g).to_bytes((&mut buf, 0)).unwrap().0,
            3 => Friends::arbitrary(g).to_bytes((&mut buf, 0)).unwrap().0,
            4 => Name::arbitrary(g).to_bytes((&mut buf, 0)).unwrap().0,
            5 => StatusMsg::arbitrary(g).to_bytes((&mut buf, 0)).unwrap().0,
            6 => UserStatus::arbitrary(g).to_bytes((&mut buf, 0)).unwrap().0,
            0x0a => TcpRelays::arbitrary(g).to_bytes((&mut buf, 0)).unwrap().0,
            0x0b => PathNodes::arbitrary(g).to_bytes((&mut buf, 0)).unwrap().0,
            _ => {
                debug!("system error: gen_range() error");
                NospamKeys::arbitrary(g).to_bytes((&mut buf, 0)).unwrap().0
            },
        };
        let kind = SectionKind::arbitrary(g);

        SectionData { kind, data: data.to_vec() }
    }
}


/** Sections of state format.

https://zetok.github.io/tox-spec/#sections
*/
#[derive(Clone, Debug, Eq, PartialEq)]
// TODO: deduplicate with `SectionKind` ?
pub enum Section {
    /** Section for [`NoSpam`](../../toxid/struct.NoSpam.html), public and
    secret keys.

    https://zetok.github.io/tox-spec/#nospam-and-keys-0x01
    */
    NospamKeys(NospamKeys),
    /** Section for DHT-related data – [`DhtState`](./struct.DhtState.html).

    https://zetok.github.io/tox-spec/#dht-0x02
    */
    DHT(DhtState),
    /** Section for friends data. Contains list of [`Friends`]
    (./struct.Friends.html).

    https://zetok.github.io/tox-spec/#friends-0x03
    */
    Friends(Friends),
    /** Section for own [`StatusMsg`](./struct.StatusMsg.html).

    https://zetok.github.io/tox-spec/#status-message-0x05
    */
    Name(Name),
    /** Section for own [`StatusMsg`](./struct.StatusMsg.html).

    https://zetok.github.io/tox-spec/#status-message-0x05
    */
    StatusMsg(StatusMsg),
    /** Section for own [`UserStatus`](./enum.UserStatus.html).

    https://zetok.github.io/tox-spec/#status-0x06
    */
    Status(UserStatus),
    /** Section for a list of [`TcpRelays`](./struct.TcpRelays.html).

    https://zetok.github.io/tox-spec/#tcp-relays-0x0a
    */
    TcpRelays(TcpRelays),
    /** Section for a list of [`PathNodes`](./struct.PathNodes.html) for onion
    routing.

    https://zetok.github.io/tox-spec/#path-nodes-0x0b
    */
    PathNodes(PathNodes),
}


/** Tox State sections. Use to manage `.tox` save files.

https://zetok.github.io/tox-spec/#state-format
*/
#[derive(Clone, Debug, Default, Eq, PartialEq)]
// TODO: change to use `Section`s
pub struct State {
    // Sections are listed in order from the spec.
    nospamkeys: NospamKeys,
    dhtstate: DhtState,
    friends: Friends,
    name: Name,
    status_msg: StatusMsg,
    status: UserStatus,
    tcp_relays: TcpRelays,
    path_nodes: PathNodes,
}

/// State Format magic bytes.
const STATE_MAGIC: &[u8; 4] = &[0x1f, 0x1b, 0xed, 0x15];

/// Length of `State` header.
#[cfg(test)]
const STATE_HEAD_LEN: usize = 8;


// TODO: refactor the whole thing
impl State {

    /** Add friend with `PublicKey` without sending a friend request.

    Returns `true` if friend was added, `false` otherwise.

    **Subject to change**.
    */
    // TODO: move elsewhere
    pub fn add_friend_norequest(&mut self, pk: &PublicKey) -> bool {
        self.friends.add_friend(FriendState::new_from_pk(pk))
    }

    /** Check if given `PublicKey` is an exact match to the `State` PK.

    When checking if given Tox ID is our own, check only PK part, as it is
    the only usable unchanging part.

    Returns `true` if there's an exact match, `false` otherwise.
    */
    pub fn is_own_pk(&self, pk: &PublicKey) -> bool {
        self.nospamkeys.pk == *pk
    }

    /** Fails (returns `None`) only if there is no `NospamKeys` in supplied
    sections. If some other section than `NospamKeys` has invalid data,
    `Default` value is used.
    */
    // TODO: test
    fn from_sects(sects: &[Section]) -> Option<Self> {
        // if no section matches `NospamKeys` return early
        if !sects.iter()
            .any(|s| match *s { Section::NospamKeys(_) => true, _ => false })
        {
            return None
        }

        // TODO: ↓ refactor once Eof gets implemented

        // get the section, or `Default` if section doesn't exist
        macro_rules! state_section {
            ($pname: path) => (
                sects.iter()
                    .filter_map(|s| match *s {
                        $pname(ref s) => Some(s.clone()),
                        _ => None,
                    })
                    .next()
                    .unwrap_or_default()
            )
        }

        // return `Some(_)` only if there are valid `NospamKeys`
        sects.iter()
            .filter_map(|s| match *s {
                Section::NospamKeys(ref nspks) => Some(nspks.clone()),
                _ => None,
            })
            .next()
            .map(|nspks|
                State {
                    nospamkeys: nspks,
                    dhtstate: state_section!(Section::DHT),
                    friends: state_section!(Section::Friends),
                    name: state_section!(Section::Name),
                    status_msg: state_section!(Section::StatusMsg),
                    status: state_section!(Section::Status),
                    tcp_relays: state_section!(Section::TcpRelays),
                    path_nodes: state_section!(Section::PathNodes),
                }
            )
    }
}

impl FromBytes for State {
    named!(from_bytes<State>, do_parse!(
        tag!(&[0; 4]) >>
        tag!(STATE_MAGIC) >>
        sections: map!(many0!(SectionData::from_bytes), |ref sd| SectionData::into_sect_mult(sd)) >>
        state: expr_opt!(Self::from_sects(&sections)) >>
        (state)
    ));
}

impl ToBytes for State {
    // unoptimized
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_slice!(&[0; 4]) >>
            gen_slice!(STATE_MAGIC) >>
            gen_call!(|buf, nospamkeys| NospamKeys::to_bytes(nospamkeys, buf), &self.nospamkeys) >>
            gen_call!(|buf, friends| Friends::to_bytes(friends, buf), &self.friends) >>
            gen_call!(|buf, name| Name::to_bytes(name, buf), &self.name) >>
            gen_call!(|buf, status_msg| StatusMsg::to_bytes(status_msg, buf), &self.status_msg) >>
            gen_call!(|buf, status| UserStatus::to_bytes(status, buf), &self.status) >>
            gen_call!(|buf, dhtstate| DhtState::to_bytes(dhtstate, buf), &self.dhtstate) >>
            gen_call!(|buf, tcp_relays| TcpRelays::to_bytes(tcp_relays, buf), &self.tcp_relays) >>
            gen_call!(|buf, path_nodes| PathNodes::to_bytes(path_nodes, buf), &self.path_nodes)
        )
    }
}

#[cfg(test)]
impl Arbitrary for State {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        macro_rules! arb_state_section {
            ($($section:ident),+) => (
                State {
                    $($section: Arbitrary::arbitrary(g),)+
                }
            )
        }
        arb_state_section!(nospamkeys, friends, name, status_msg, status,
                           dhtstate, tcp_relays, path_nodes)
    }
}



// FriendState::

// FriendState::new_from_pk()

#[test]
fn friend_state_new_from_pk_test() {
    fn with_pkbytes(bytes: Vec<u8>) -> TestResult {
        if bytes.len() < PUBLICKEYBYTES {
            return TestResult::discard()
        }

        let pk = PublicKey::from_slice(&bytes[..PUBLICKEYBYTES]).unwrap();

        let fs = FriendState::new_from_pk(&pk);

        assert_eq!(FriendStatus::Added, fs.status);
        assert_eq!(pk, fs.pk);
        assert!(fs.fr_msg.is_empty());
        assert!(fs.name.0.is_empty());
        assert!(fs.status_msg.0.is_empty());
        assert_eq!(UserStatus::Online, fs.user_status);
        assert_eq!(NoSpam([0; NOSPAMBYTES]), fs.nospam);
        assert_eq!(0, fs.last_seen);

        TestResult::passed()
    }
    quickcheck(with_pkbytes as fn(Vec<u8>) -> TestResult);
}

// FriendState::from_bytes()

#[test]
fn friend_state_from_bytes_test() {
    // serialized and deserialized remain the same
    fn assert_success(bytes: &[u8], friend_state: &FriendState) {
        let (_, ref p) = FriendState::from_bytes(bytes).unwrap();
        assert_eq!(friend_state, p);
    }

    fn with_fs(fs: FriendState) {
        let mut buf = [0u8; 1024];
        let fs_bytes = fs.to_bytes((&mut buf, 0)).unwrap().0;
        assert_success(&fs_bytes, &fs);

        for b in 0..(FRIENDSTATEBYTES - 1) {
            assert!(FriendState::from_bytes(&fs_bytes[..b]).is_incomplete());
        }

        { // FriendStatus
            let mut bytes = Vec::new();
            bytes.clone_from_slice(fs_bytes);
            // TODO: change to inclusive range (`...`) once gets stabilised
            //       rust #28237
            for b in 5..u8::max_value() {
                bytes[0] = b;
                assert!(FriendState::from_bytes(&bytes).is_err());
            }
        }

        const FR_MSG_LEN_POS: usize = 1 + PUBLICKEYBYTES + REQUEST_MSG_LEN + 1;
        { // friend request message lenght check
            let mut bytes = Vec::new();
            bytes.clone_from_slice(fs_bytes);
            for i in (REQUEST_MSG_LEN+1)..2500 { // too slow with bigger ranges
                BigEndian::write_u16(&mut bytes[FR_MSG_LEN_POS..], i as u16);
                assert!(FriendState::from_bytes(&bytes).is_err());
            }
        }

        const NAME_LEN_POS: usize = FR_MSG_LEN_POS + NAME_LEN + 2;
        { // friend name lenght check
            let mut bytes = Vec::new();
            bytes.clone_from_slice(fs_bytes);
            for i in (NAME_LEN+1)..2500 { // too slow with bigger ranges
                BigEndian::write_u16(&mut bytes[NAME_LEN_POS..], i as u16);
                assert!(FriendState::from_bytes(&bytes).is_err());
            }
        }

        // padding + bytes containing length
        const STATUS_MSG_LEN_POS: usize = NAME_LEN_POS + STATUS_MSG_LEN + 3;
        { // friend name lenght check
            let mut bytes = Vec::new();
            bytes.clone_from_slice(fs_bytes);
            for i in (STATUS_MSG_LEN+1)..2500 { // too slow with bigger ranges
                BigEndian::write_u16(&mut bytes[STATUS_MSG_LEN_POS..], i as u16);
                assert!(FriendState::from_bytes(&bytes).is_err());
            }
        }


        const USTATUS_POS: usize = STATUS_MSG_LEN_POS + 2;
        { // user status
            fn has_status(bytes: &[u8], status: UserStatus) {
                let (_, fs) = FriendState::from_bytes(bytes).unwrap();
                assert_eq!(fs.user_status, status);
            }

            let mut bytes = Vec::new();
            bytes.clone_from_slice(fs_bytes);

            // TODO: change to inclusive range (`...`) once gets stabilised
            //       rust #28237
            for i in 0..u8::max_value() {
                bytes[USTATUS_POS] = i;

                match i {
                    0 => has_status(&bytes, UserStatus::Online),
                    1 => has_status(&bytes, UserStatus::Away),
                    2 => has_status(&bytes, UserStatus::Busy),
                    _ => assert!(FriendState::from_bytes(&bytes).is_err()),
                }
            }
        }

        const PADDING_POS: usize = USTATUS_POS + 1;
        { // padding; should be always ignored when parsing
            let mut bytes = Vec::new();
            bytes.clone_from_slice(fs_bytes);
            // TODO: change to inclusive range (`...`) once gets stabilised
            //       rust #28237
            for i in 0..u8::max_value() {
                bytes[PADDING_POS]   = i;
                bytes[PADDING_POS+1] = i;
                bytes[PADDING_POS+2] = i;
                assert_success(&bytes, &fs);
            }
        }

        // TODO: test for:
        //
        // nospam
        //
        // last time seen
    }
    quickcheck(with_fs as fn(FriendState));
}


// Friends::

// Friends::is_friend()

#[test]
fn friends_is_friend_test() {
    fn with_friends(friends: Friends, fstate: FriendState) -> TestResult {
        // can fail if quickcheck produces `Friends` that includes generated
        // friend
        assert_eq!(false, friends.is_friend(&fstate.pk));

        let mut friends = friends.clone();
        let pk = fstate.pk;
        friends.0.push(fstate);
        assert_eq!(true, friends.is_friend(&pk));
        TestResult::passed()
    }
    quickcheck(with_friends as fn(Friends, FriendState) -> TestResult);

    // empty
    let pk = PublicKey([0; PUBLICKEYBYTES]);
    assert_eq!(false, Friends(Vec::new()).is_friend(&pk));
}


// SectionData::

// SectionData::into_section()

// check for each type
macro_rules! section_data_with_kind_into {
    ($($kind:ident, $tname:ident),+) => ($(
        #[test]
        fn $tname() {
            fn tf(sd: SectionData) -> TestResult {
                if sd.kind != SectionKind::$kind {
                    return TestResult::discard()
                }
                assert!(sd.as_section().to_result().is_ok());
                TestResult::passed()
            }
            quickcheck(tf as fn(SectionData) -> TestResult);
        }
    )+)
}
section_data_with_kind_into!(
    NospamKeys, section_data_into_sect_test_nospamkeys,
    DHT,        section_data_into_sect_test_dht,
    Friends,    section_data_into_sect_test_friends,
    Name,       section_data_into_sect_test_name,
    StatusMsg,  section_data_into_sect_test_status_msg,
    Status,     section_data_into_sect_test_status,
    TcpRelays,  section_data_into_sect_test_tcp_relays,
    PathNodes,  section_data_into_sect_test_path_nodes
);

#[test]
fn section_data_into_section_test_random() {
    fn with_section(sd: SectionData) {
        assert!(sd.as_section().to_result().is_ok());
    }
    quickcheck(with_section as fn(SectionData));
}

// SectionData::into_sect_mult()

macro_rules! section_data_into_sect_mult_into {
    ($($sect:ty, $kind:ident, $tname:ident),+) => ($(
        #[test]
        fn $tname() {
            fn with_sects(s: Vec<$sect>) {
                let sds: Vec<SectionData> = s.iter()
                    .map(|se| {
                        let mut buf = [0u8; 2048];
                        SectionData
                        {
                            kind: SectionKind::$kind,
                            data: se.to_bytes((&mut buf, 0)).unwrap().0.to_vec()
                        }
                    })
                    .collect();
                let sections = SectionData::into_sect_mult(&sds);
                assert_eq!(s.len(), sections.len());
                if !s.is_empty() {
                    assert!(sections.iter().all(|se| match *se {
                        Section::$kind(_) => true,
                        _ => false,
                    }));
                }
            }
            QuickCheck::new().max_tests(20).quickcheck(with_sects as fn(Vec<$sect>));
        }
    )+)
}
// NOTE: ↓ this takes 5 min of CPU time on a 4GHz AMD Piledriver(!)
section_data_into_sect_mult_into!(
    NospamKeys, NospamKeys, section_data_into_sect_mult_test_nospamkeys,
    DhtState, DHT, section_data_into_sect_mult_test_dht,
    // ↓ takes longest, since it requires generating Vec<Friend> and then
    //   parsing that
    Friends, Friends, section_data_into_sect_mult_test_friends,
    Name, Name, section_data_into_sect_mult_test_name,
    StatusMsg, StatusMsg, section_data_into_sect_mult_test_status_msg,
    UserStatus, Status, section_data_into_sect_mult_test_status,
    TcpRelays, TcpRelays, section_data_into_sect_mult_test_path_nodes,
    TcpRelays, TcpRelays, section_data_into_sect_mult_test_tcp_relays
);

#[test]
fn section_data_into_sect_mult_test_random() {
    fn random_sds(sds: Vec<SectionData>) {
        assert_eq!(sds.len(), SectionData::into_sect_mult(&sds).len());
    }
    quickcheck(random_sds as fn(Vec<SectionData>));
}

// SectionData::from_bytes()

#[test]
fn section_data_from_bytes_test() {
    fn rand_b_sect(kind: SectionKind, bytes: &[u8]) -> Vec<u8> {
        let mut b_sect = Vec::with_capacity(bytes.len() + SECTION_MIN_LEN);
        b_sect.write_u32::<LittleEndian>(bytes.len() as u32).unwrap();
        b_sect.write_u16::<LittleEndian>(kind as u16).unwrap();
        b_sect.extend_from_slice(SECTION_MAGIC);
        b_sect.extend_from_slice(bytes);
        b_sect
    }

    fn with_bytes(bytes: Vec<u8>, kind: SectionKind) {
        let b_sect = rand_b_sect(kind, &bytes);

        { // working case
            let (left, section) = SectionData::from_bytes(&b_sect).unwrap();

            assert_eq!(0, left.len());
            assert_eq!(section.kind, kind);
            assert_eq!(&section.data, &bytes);
        }

        { // wrong SectionKind
            fn wrong_skind(bytes: &[u8]) {
                assert!(SectionData::from_bytes(bytes).is_err());
            }

            let mut b_sect = b_sect.clone();
            for num in 7..10 {
                b_sect[4] = num;
                wrong_skind(&b_sect);
            }
            // TODO: change to inclusive range (`...`) once gets stabilised
            //       rust #28237
            for num in 12..u8::max_value() {
                b_sect[4] = num;
                wrong_skind(&b_sect);
            }

            b_sect[4] = 1; // right
            b_sect[5] = 1; // wrong
            wrong_skind(&b_sect);
        }

        // too short
        for l in 0..SECTION_MIN_LEN {
            assert!(SectionData::from_bytes(&b_sect[..l]).is_incomplete());
        }

        // wrong len
        for l in SECTION_MIN_LEN..(b_sect.len() - 1) {
            assert!(SectionData::from_bytes(&b_sect[..l]).is_incomplete());
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>, SectionKind));

    fn with_magic(bytes: Vec<u8>, kind: SectionKind, magic: Vec<u8>)
        -> TestResult
    {
        if magic.len() < 2 || &[magic[0], magic[1]] == SECTION_MAGIC {
                return TestResult::discard()
        }

        let tmp_b_sect = rand_b_sect(kind, &bytes);
        let mut b_sect = Vec::with_capacity(tmp_b_sect.len());
        b_sect.extend_from_slice(&tmp_b_sect[..SECTION_MIN_LEN - 2]);
        b_sect.extend_from_slice(&magic[..2]);
        b_sect.extend_from_slice(&tmp_b_sect[SECTION_MIN_LEN..]);
        assert!(SectionData::from_bytes(&b_sect).is_err());
        TestResult::passed()
    }
    quickcheck(with_magic as fn(Vec<u8>, SectionKind, Vec<u8>) -> TestResult);
}


// State::

// State::add_friend_norequest()

#[test]
fn state_add_friend_norequest_test() {
    fn with_pk(state: State, pkbytes: Vec<u8>) -> TestResult {
        quick_pk_from_bytes!(pkbytes, pk);

        let mut new_state = state.clone();

        assert!(new_state.add_friend_norequest(&pk));
        assert_eq!(false, new_state.add_friend_norequest(&pk));
        assert!(state != new_state);
        assert_eq!(state.friends.0.len() + 1, new_state.friends.0.len());

        let popped = new_state.friends.0.pop().expect("Friend");
        assert_eq!(state, new_state);
        assert_eq!(popped, FriendState::new_from_pk(&pk));

        TestResult::passed()
    }
    quickcheck(with_pk as fn(State, Vec<u8>) -> TestResult);
}

// State::is_own_pk()

#[test]
fn state_is_own_pk_test() {
    fn with_pk(state: State, bytes: Vec<u8>) -> TestResult {
        quick_pk_from_bytes!(bytes, rand_pk);

        assert!(state.is_own_pk(&state.nospamkeys.pk));
        assert_eq!(false, state.is_own_pk(&rand_pk));
        TestResult::passed()
    }
    quickcheck(with_pk as fn(State, Vec<u8>) -> TestResult);
}

// State::from_bytes()

#[test]
fn state_from_bytes_test_magic() {
    fn with_state(state: State, rand_bytes: Vec<u8>) -> TestResult {
        if rand_bytes.len() < STATE_HEAD_LEN {
            return TestResult::discard()
        }

        let mut buf = [0u8; 1024];
        let state_bytes = state.to_bytes((&mut buf, 0)).unwrap().0;
        assert!(State::from_bytes(&state_bytes).is_done());

        let mut invalid_bytes = Vec::with_capacity(state_bytes.len());
        invalid_bytes.extend_from_slice(&rand_bytes[..STATE_HEAD_LEN]);
        invalid_bytes.extend_from_slice(&state_bytes[STATE_HEAD_LEN..]);
        assert!(State::from_bytes(&invalid_bytes).is_err());
        TestResult::passed()
    }
    quickcheck(with_state as fn(State, Vec<u8>) -> TestResult);
}

#[test]
fn state_from_bytes_test_section_detect() {
    fn with_state(state: State, rand_byte: u8) -> TestResult {
        if rand_byte == SECTION_MAGIC[0] {
            return TestResult::discard()
        }

        let mut buf = [0u8; 1024];
        let bytes: Vec<u8> = state.to_bytes((&mut buf, 0)).unwrap().0.iter_mut()
            .map(|b| { if *b == SECTION_MAGIC[0] { *b = rand_byte; } *b })
            .collect();

        assert!(State::from_bytes(&bytes).is_err());

        TestResult::passed()
    }
    quickcheck(with_state as fn(State, u8) -> TestResult);
    with_state(State::default(), SECTION_MAGIC[0]);
}
