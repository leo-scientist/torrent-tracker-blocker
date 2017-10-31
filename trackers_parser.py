import argparse
import csv
import fileinput
import socket
import sys

from urllib.parse import urlparse


class TrackersParser:
    def __init__(self, input_file, output_file):
        self.file = input_file
        self.output_file = output_file

    def parse_file(self):
        # Generator object for read lines from file
        strp_lines = (x for x in self.file if "".join(x.split()).rstrip('\n'))

        for line in strp_lines:
            self.save_line_to_file(urlparse(line))

    def prepare_ip(self, host):
        try:
            socket.inet_aton(host)
            return host
        except socket.error:
            try:
                return socket.gethostbyname(host)
            except socket.error:
                return None
        return None

    def save_line_to_file(self, url):
        allowed_list = ['127.0.0.1']
        csv_writer = csv.writer(self.output_file)
        url_hostname = self.prepare_ip(url.hostname)
        if url_hostname and url_hostname not in allowed_list:
            csv_writer.writerow([url.scheme if url.scheme else '',
                                url.port if url.port else '80',
                                url_hostname])

    def remove_dublicates(self):
        seen = set()
        for line in fileinput.FileInput(self.file.name, inplace=1):
            if line in seen:
                continue
            seen.add(line)
            print(line, end='')

    def main(self):
        self.remove_dublicates()
        self.parse_file()
        self.remove_dublicates()


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(
        description='Parse text file with list of trackers and save it to csv')
    arg_parser.add_argument('-i', help='Input text file path.',
                            type=argparse.FileType('r'), action='store',
                            dest='input', metavar='--in', required=True)
    arg_parser.add_argument('-o', help='Output CSV file path.',
                            default='trackers.csv', action='store',
                            type=argparse.FileType('w+'), dest='output',
                            metavar='--out')
    args = arg_parser.parse_args()

    tp = TrackersParser(args.input, args.output)
    tp.main()
