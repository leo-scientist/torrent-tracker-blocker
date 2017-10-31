import argparse
import csv
import iptc


class SyncIptables:
    def __init__(self, trackers_file, chain):
        self.trackers_file = trackers_file
        self.chain = chain
        self.input_chain = '{0}-input'.format(chain)
        self.output_chain = '{0}-output'.format(chain)
        self.forward_chain = '{0}-forward'.format(chain)
        self.table = iptc.Table(iptc.Table.FILTER)

    def remove_old_rules(self):
        # Remove chain with rules if exists
        for chain in self.table.chains:
            for rule in chain.rules:
                if self.chain in rule.target.name:
                    chain.delete_rule(rule)

        for chain in [self.input_chain, self.output_chain,
                      self.forward_chain]:
            if chain in [x.name for x in self.table.chains]:
                iptc.Chain(self.table, chain).flush()
                iptc.Chain(self.table, chain).delete()

    def apply_new_rules(self):
        # Create new chain
        input_chain = self.table.create_chain(self.input_chain)
        output_chain = self.table.create_chain(self.output_chain)
        forward_chain = self.table.create_chain(self.forward_chain)

        rule = iptc.Rule()
        chains = [['INPUT', self.input_chain],
                  ['OUTPUT', self.output_chain],
                  ['FORWARD', self.forward_chain]]

        for o_chain, n_chain in chains:
            rule.target = iptc.Target(rule, n_chain)
            iptc.Chain(self.table, o_chain).append_rule(rule)

        for row in csv.reader(self.trackers_file):
            # Apply new rules from CSV to input chain
            in_rule = iptc.Rule()
            in_rule.src = row[2]
            in_rule.protocol = row[0] if row[0].lower() == 'udp' else 'tcp'
            in_match = iptc.Match(in_rule, in_rule.protocol)
            in_match.sport = row[1] if row[1].isdigit() else '80'
            in_rule.add_match(in_match)
            in_rule.target = iptc.Target(in_rule, 'DROP')
            input_chain.insert_rule(in_rule)

            # Apply new rules from CSV to output chain
            out_rule = iptc.Rule()
            out_rule.dst = row[2]
            out_rule.protocol = row[0] if row[0].lower() == 'udp' else 'tcp'
            out_match = iptc.Match(out_rule, out_rule.protocol)
            out_match.dport = row[1] if row[1].isdigit() else '80'
            out_rule.add_match(out_match)
            out_rule.target = iptc.Target(out_rule, 'DROP')
            output_chain.insert_rule(out_rule)

            # Apply new rules from CSV to forward chain
            forw_rule = iptc.Rule()
            forw_rule.dst = row[2]
            forw_rule.protocol = row[0] if row[0].lower() == 'udp' else 'tcp'
            forw_match = iptc.Match(forw_rule, forw_rule.protocol)
            forw_match.dport = row[1] if row[1].isdigit() else '80'
            forw_rule.add_match(forw_match)
            forw_rule.target = iptc.Target(forw_rule, 'DROP')
            forward_chain.insert_rule(forw_rule)

    def main(self):
        self.remove_old_rules()
        self.apply_new_rules()


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(
        description='Sync torrent trackers list with iptables')
    arg_parser.add_argument('-r', help='Remove rules', action='store_true',
                            dest='remove', default=False)
    arg_parser.add_argument('-i', help='Input CSV file path.',
                            type=argparse.FileType('r'), action='store',
                            dest='input', metavar='--in', required=True)
    arg_parser.add_argument('-c', help='Chain name', action='store',
                            dest='chain', metavar='--chain', default='aw-vpn')
    args = arg_parser.parse_args()
    sync = SyncIptables(args.input, args.chain)
    sync.main()
