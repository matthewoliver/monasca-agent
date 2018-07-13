import errno
import os

import monasca_agent.collector.checks as checks

from collections import defaultdict

from swift.common.storage_policy import split_policy_string
from swift.obj.diskfile import get_data_dir
from swift.common.ring import Ring


def get_ring_and_datadir(path):
    """
    :param path: path to ring

    :returns: a tuple, (ring, datadir)
    """
    ring_name = os.path.basename(path).split('.')[0]
    base, policy = split_policy_string(ring_name)
    if base == 'object':
        datadir = get_data_dir(policy)
    else:
        datadir = base + 's'
    return Ring(path), ring_name, datadir


class SwiftHandoffs(checks.AgentCheck):

    def check(self, instance):
        device_root = instance.get('devices', '/srv/node')
        if not os.path.exists(device_root) or not os.path.isdir(device_root):
            self.log.error('devices must exist or be a directory')
            return None

        ring_path = instance.get('ring', '/etc/swift/object.ring.gz')
        if not os.path.exists(ring_path) or not os.path.isfile(ring_path):
            self.log.error('ring must exist')
            return None

        granularity = instance.get('granularity', 'server').lower()
        if granularity not in ('server', 'device'):
            self.log.error("granularity must be either 'server' or 'drive'")
            return None

        ring, ring_name, datadir = get_ring_and_datadir(ring_path)

        dev2parts = defaultdict(set)
        for replica, part2dev in enumerate(ring._replica2part2dev_id):
            for part, device_id in enumerate(part2dev):
                dev2parts[ring.devs[device_id]['device']].add(part)

        # print dev2parts
        primary_count = defaultdict(int)
        handoffs = defaultdict(set)
        device_dirs = os.listdir(device_root)
        for device_dir in device_dirs:
            parts_dir = os.path.join(device_root, device_dir, datadir)
            try:
                parts = os.listdir(parts_dir)
            except OSError as e:
                if e.errno == errno.ENOENT:
                    continue
                else:
                    raise
            for part in parts:
                if not part.isdigit():
                    continue
                part = int(part)
                if part in dev2parts[device_dir]:
                    primary_count[device_dir] += 1
                else:
                    handoffs[device_dir].add(part)

        dimensions = {'ring': ring_name}
        dimensions = self._set_dimensions(dimensions, instance)
        if granularity == 'server':
            self.gauge('swift_handoffs.primary',
                       sum(primary_count.values()), dimensions.copy())
            self.gauge('swift_handoffs.handoffs',
                       sum(map(len, handoffs.values())), dimensions)
        else:
            for device in device_dirs:
                tmp_dimensions = dimensions.copy()
                tmp_dimensions['device'] = device
                self.gauge('swift_handoffs.primary',
                           primary_count[device], tmp_dimensions)
                self.gauge('swift_handoffs.handoffs',
                           len(handoffs[device]), tmp_dimensions)
