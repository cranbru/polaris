# collectors package - static registration for standalone portable execution

try:
    from collectors.execution import (
        prefetch,
        amcache,
        shimcache,
        bam,
        srum,
        userassist,
        pca,
        powershell_artifacts,
    )
    from collectors.eventlogs import evtx_collector
    from collectors.user_activity import (
        lnk_collector,
        jump_lists,
        recent_docs,
        shellbags,
        recycle_bin,
    )
    from collectors.registry import hive_collector, registry_artifacts
    from collectors.browsers import chrome, edge, firefox
    from collectors.devices import usb_collector
    from collectors.persistence import persistence_collector
    from collectors.network import network_collector
    from collectors.system import system_collector
except ImportError:
    pass


