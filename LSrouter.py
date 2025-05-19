####################################################
# LSrouter.py
# Name: <Your Name>
# HUID: <Your HUID>
#####################################################

from router import Router
from packet import Packet
import json
import heapq

class LSrouter(Router):
    """Link state routing protocol implementation."""

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # Initialize base class - DO NOT REMOVE
        self.heartbeat_time = heartbeat_time
        self.last_time = 0

        # Local neighbors: port -> (neighbor_addr, cost)
        self.neighbors = {}
        # Link state database: router_addr -> list of (neighbor, cost, port)
        self.link_state_db = {addr: []}
        # Highest sequence number seen: router_addr -> seq_num
        self.seq_lsa = {addr: 0}
        # Own sequence number
        self.seq_num = 0
        # Forwarding table: destination -> out_port
        self.routing_table = {}

    def broadcast(self, content=None, sender=None):
        """Flood an LSA packet (new or received) to all neighbors except sender."""
        if content is None:
            # Build current LSA payload
            lsa = {
                'router': self.addr,
                'seq_num': self.seq_num,
                'links': {nbr: [cost, port] for port, (nbr, cost) in self.neighbors.items()}
            }
            content = json.dumps(lsa)
        # Send to each neighbor
        for port, (nbr, _) in self.neighbors.items():
            if nbr == sender:
                continue
            pkt = Packet(Packet.ROUTING, self.addr, nbr, content)
            self.send(port, pkt)

    def _rebuild_routing_table(self):
        """Rebuild forwarding table using Dijkstra on link_state_db."""
        dist = {self.addr: 0}
        prev = {}
        visited = set()
        pq = [(0, self.addr)]

        while pq:
            d, u = heapq.heappop(pq)
            if u in visited:
                continue
            visited.add(u)
            for v, cost, _ in self.link_state_db.get(u, []):
                nd = d + cost
                if v not in dist or nd < dist[v]:
                    dist[v] = nd
                    prev[v] = u
                    heapq.heappush(pq, (nd, v))

        # Build routing table mapping dest -> next-hop port
        self.routing_table.clear()
        for dst in dist:
            if dst == self.addr:
                continue
            # trace path back to find next hop
            hop = dst
            while prev.get(hop) != self.addr:
                hop = prev[hop]
            # find outbound port for next hop
            for port, (nbr, _) in self.neighbors.items():
                if nbr == hop:
                    self.routing_table[dst] = port
                    break

    def handle_packet(self, port, packet):
        """Process incoming packet: traceroute or routing update."""
        if packet.is_traceroute:
            # Data packet: forward if entry exists
            out_port = self.routing_table.get(packet.dst_addr)
            if out_port is not None:
                self.send(out_port, packet)
            return

        # Routing packet: parse LSA
        data = json.loads(packet.content)
        adv = data['router']
        seq = data['seq_num']
        links = data['links']  # neighbor -> [cost, port]

        # Discard old LSA
        if seq <= self.seq_lsa.get(adv, 0):
            return
        # Record new seq
        self.seq_lsa[adv] = seq
        # Update LSDB entry
        entries = []
        for nbr, (cost, prt) in links.items():
            entries.append((nbr, cost, prt))
        self.link_state_db[adv] = entries
        # Flood to other neighbors
        self.broadcast(content=packet.content, sender=packet.src_addr)
        # Rebuild routing table
        self._rebuild_routing_table()

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link event."""
        # Record neighbor and update LSDB immediately
        self.neighbors[port] = (endpoint, cost)
        self.link_state_db[self.addr] = [e for e in self.link_state_db[self.addr] if e[0] != endpoint]
        self.link_state_db[self.addr].append((endpoint, cost, port))
        # Increment sequence and record
        self.seq_num += 1
        self.seq_lsa[self.addr] = self.seq_num
        # Broadcast updated LSA
        self.broadcast()
        # Rebuild routing table
        self._rebuild_routing_table()

    def handle_remove_link(self, port):
        """Handle removal of a link."""
        if port not in self.neighbors:
            return
        endpoint, _ = self.neighbors.pop(port)
        self.link_state_db[self.addr] = [e for e in self.link_state_db[self.addr] if e[0] != endpoint]
        self.seq_num += 1
        self.seq_lsa[self.addr] = self.seq_num
        self.broadcast()
        self._rebuild_routing_table()

    def handle_time(self, time_ms):
        """Periodic heartbeat to rebroadcast LSA."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self.seq_num += 1
            self.seq_lsa[self.addr] = self.seq_num
            self.broadcast()

    def __repr__(self):
        return f"LSrouter(addr={self.addr}, routing_table={self.routing_table})"
