/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2018 Namsoo CHO <nscho66@gmail.com>

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


/*!
Save or load states of tox daemon.
When toxcore start, it load states from saved file.
Toxcore daemon saves its states to file every 10 minutes.
*/

use toxcore::dht::server::*;
use toxcore::dht::packed_node::*;
use toxcore::dht::server::client::*;
use toxcore::state_format::rs_new::*;
use toxcore::binary_io::*;

/// Save or load states of toxcore daemon
#[derive(Clone, Debug)]
pub struct DaemonState;

impl DaemonState {
    /// save states
    pub fn save(server: &Server) -> Vec<u8> {
        let nodes = server.close_nodes.read().iter()
            .map(|node| node.into())
            .collect::<Vec<PackedNode>>();

        let mut buf = [0u8; 512];
        if let Ok((_, buf_len)) = DhtState(nodes).to_bytes((&mut buf, 0)) {
            buf[..buf_len].to_vec()
        } else {
            Vec::new()
        }
    }

    /// load states
    pub fn load(server: &Server, saved_data: Vec<u8>) {
        let nodes = match DhtState::from_bytes(&saved_data) {
            IResult::Done(_, DhtState(nodes)) => nodes,
            _ => {
                debug!("Can't load saved DHT status");
                return
            },
        };

        let mut ping_map = server.ping_map.write();
        nodes.iter()
            .for_each(|node| {
                let client = ping_map.entry(node.pk).or_insert_with(PingData::new);

                server.send_nodes_req(*node, server.pk, client);
            });
    }
}


