import logging


def convert_str_to_bool(value):
    """
    Convert true/false/yes/no/1/0 to boolean
    """

    if isinstance(value, bool):
        return value

    value = str(value).lower()
    if value in ['1', 'true', 'yes']:
        return True
    elif value in ['0', 'false', 'no']:
        return False
    raise ValueError(value)


class Setting(object):
    def __init__(self, name, type_str, def_val):
        self.name = name
        self.type_str = type_str
        self.def_val = def_val

    def __contains__(self, key):
        return key == self.def_val


class BoolSetting(Setting):
    def __init__(self, name, def_val):
        super(BoolSetting, self).__init__(name, "bool", def_val)

    def to_str(self, norm_val):
        if norm_val:
            return "true"
        else:
            return "false"

    def normalize(self, raw_val):
        try:
            # for compat we also support Yes/No and 1/0
            return convert_str_to_bool(raw_val)
        except ValueError:
            raise ValueError("expected true or false for {}".format(self.name))


class LIOBoolSetting(BoolSetting):
    def __init__(self, name, def_val):
        super(LIOBoolSetting, self).__init__(name, def_val)

    def to_str(self, norm_val):
        if norm_val:
            return "yes"
        else:
            return "no"

    def normalize(self, raw_val):
        try:
            # for compat we also support True/False and 1/0
            return convert_str_to_bool(raw_val)
        except ValueError:
            raise ValueError("expected yes or no for {}".format(self.name))


class ListSetting(Setting):
    def __init__(self, name, def_val):
        super(ListSetting, self).__init__(name, "list", def_val)

    def to_str(self, norm_val):
        return str(norm_val)

    def normalize(self, raw_val):
        return [r.strip() for r in raw_val.split(',')] if raw_val else []


class StrSetting(Setting):
    def __init__(self, name, def_val):
        super(StrSetting, self).__init__(name, "str", def_val)

    def to_str(self, norm_val):
        return str(norm_val)

    def normalize(self, raw_val):
        return str(raw_val)


class IntSetting(Setting):
    def __init__(self, name, min_val, max_val, def_val):
        self.min_val = min_val
        self.max_val = max_val
        super(IntSetting, self).__init__(name, "int", def_val)

    def to_str(self, norm_val):
        return str(norm_val)

    def normalize(self, raw_val):
        try:
            val = int(raw_val)
        except ValueError:
            raise ValueError("expected integer for {}".format(self.name))

        if val < self.min_val:
            raise ValueError("expected integer >= {} for {}".
                             format(self.min_val, self.name))
        if val > self.max_val:
            raise ValueError("expected integer <= {} for {}".
                             format(self.max_val, self.name))
        return val


class EnumSetting(Setting):
    def __init__(self, name, valid_vals, def_val):
        if len(valid_vals) == 0:
            raise ValueError("Invalid enum. There must be at least one valid value.")

        valid_type = type(valid_vals[0])
        if valid_type is not int and valid_type is not str:
            raise ValueError("Invalid enum. Items must be str or int. Got {}".
                             format(valid_type))

        for i in valid_vals:
            if valid_type != type(i):
                raise ValueError("Invalid enum. All items must be the same type."
                                 "Found {} and {}".format(type(i), valid_type))

        self.valid_vals = valid_vals
        super(EnumSetting, self).__init__(name, "enum", def_val)

    def to_str(self, norm_val):
        return str(norm_val)

    def normalize(self, raw_val):
        if isinstance(self.valid_vals[0], str):
            val = str(raw_val)
        else:
            val = int(raw_val)

        if val not in self.valid_vals:
            raise ValueError("expected {} for {} found {}".
                             format(self.valid_vals, self.name, raw_val))

        return val


CLIENT_SETTINGS = {
    "dataout_timeout": IntSetting("dataout_timeout", 2, 60, 20),
    "nopin_response_timeout": IntSetting("nopin_response_timeout", 3, 60, 5),
    "nopin_timeout": IntSetting("nopin_timeout", 3, 60, 5),
    "cmdsn_depth": IntSetting("cmdsn_depth", 1, 512, 128)}

TGT_SETTINGS = {
    # client settings you can also set at the ceph-iscsi target level
    "dataout_timeout": IntSetting("dataout_timeout", 2, 60, 20),
    "nopin_response_timeout": IntSetting("nopin_response_timeout", 3, 60, 5),
    "nopin_timeout": IntSetting("nopin_timeout", 3, 60, 5),
    "cmdsn_depth": IntSetting("cmdsn_depth", 1, 512, 128),
    # lio tpg settings
    "immediate_data": LIOBoolSetting("immediate_data", True),
    "initial_r2t": LIOBoolSetting("initial_r2t", True),
    "max_outstanding_r2t": IntSetting("max_outstanding_r2t", 1, 65535, 1),
    "first_burst_length": IntSetting("first_burst_length", 512, 16777215, 262144),
    "max_burst_length": IntSetting("max_burst_length", 512, 16777215, 524288),
    "max_recv_data_segment_length": IntSetting("max_recv_data_segment_length",
                                               512, 16777215, 262144),
    "max_xmit_data_segment_length": IntSetting("max_xmit_data_segment_length",
                                               512, 16777215, 262144)}

TGT_KERNEL_SETTINGS = {
    "default_cmdsn_depth": IntSetting("default_cmdsn_depth", 1, 512, 64),
    "default_erl": EnumSetting("default_erl", [0, 1, 2], 0),
    "login_timeout": IntSetting("login_timeout", 5, 30, 15),
    "netif_timeout": IntSetting("netif_timeout", 2, 15, 2),
    "prod_mode_write_protect": EnumSetting("prod_mode_write_protect", [0, 1], 0),
    "t10_pi": EnumSetting("t10_pi", [0, 1], 0)}

SYS_SETTINGS = {
    "cluster_name": StrSetting("cluster_name", "ceph"),
    "pool": StrSetting("pool", "rbd"),
    "cluster_client_name": StrSetting("cluster_client_name", "client.admin"),
    "time_out": IntSetting("time_out", 1, 600, 30),
    "api_host": StrSetting("api_host", "::"),
    "api_port": IntSetting("api_port", 1, 65535, 5000),
    "api_secure": BoolSetting("api_secure", True),
    "api_ssl_verify": BoolSetting("api_ssl_verify", False),
    "loop_delay": IntSetting("loop_delay", 1, 60, 2),
    "trusted_ip_list": ListSetting("trusted_ip_list", []),  # comma separate list of IPs
    "api_user": StrSetting("api_user", "admin"),
    "api_password": StrSetting("api_password", "admin"),
    "ceph_user": StrSetting("ceph_user", "admin"),
    "debug": BoolSetting("debug", False),
    "minimum_gateways": IntSetting("minimum_gateways", 1, 9999, 2),
    "ceph_config_dir": StrSetting("ceph_config_dir", '/etc/ceph'),
    "gateway_conf": StrSetting("gateway_conf", 'gateway.conf'),
    "priv_key": StrSetting("priv_key", 'iscsi-gateway.key'),
    "pub_key": StrSetting("pub_key", 'iscsi-gateway-pub.key'),
    "prometheus_exporter": BoolSetting("prometheus_exporter", True),
    "prometheus_port": IntSetting("prometheus_port", 1, 65535, 9287),
    "prometheus_host": StrSetting("prometheus_host", "::"),
    "logger_level": IntSetting("logger_level", logging.DEBUG, logging.CRITICAL,
                               logging.DEBUG),
    "log_to_stderr": BoolSetting("log_to_stderr", False),
    "log_to_stderr_prefix": StrSetting("log_to_stderr_prefix", ""),
    "log_to_file": BoolSetting("log_to_file", True),
    # TODO: This is under sys for compat. It is not settable per device/backend
    # type yet.
    "alua_failover_type": EnumSetting("alua_failover_type",
                                      ["implicit", "explicit"], "implicit")}

TCMU_SETTINGS = {
    "max_data_area_mb": IntSetting("max_data_area_mb", 1, 2048, 8),
    "qfull_timeout": IntSetting("qfull_timeout", 0, 600, 5),
    "osd_op_timeout": IntSetting("osd_op_timeout", 0, 600, 30),
    "hw_max_sectors": IntSetting("hw_max_sectors", 1, 8192, 1024)}

TCMU_DEV_STATUS_SETTINGS = {
    "lock_lost_cnt_threshhold": IntSetting("lock_lost_cnt_threshhold", 1, 1000000, 12),
    "status_check_interval": IntSetting("status_check_interval", 1, 600, 10),
    "stable_state_reset_count": IntSetting("stable_state_reset_count", 1, 600, 3)}

KERNEL_SETTINGS = {
    "block_size": EnumSetting("block_size", [512, 1024, 2048, 4096], 512),
    "emulate_3pc": EnumSetting("emulate_3pc", [0, 1], 1),
    "emulate_caw": EnumSetting("emulate_caw", [0, 1], 1),
    "emulate_dpo": EnumSetting("emulate_dpo", [0, 1], 1),
    "emulate_fua_read": EnumSetting("emulate_fua_read", [0, 1], 1),
    "emulate_fua_write": EnumSetting("emulate_fua_write", [0, 1], 1),
    "emulate_legacy_capacity": EnumSetting("emulate_legacy_capacity", [0, 1], 1),
    "emulate_model_alias": EnumSetting("emulate_model_alias", [0, 1], 0),
    "emulate_pr": EnumSetting("emulate_pr", [0, 1], 1),
    "emulate_rest_reord": EnumSetting("emulate_rest_reord", [0, 1], 1),
    "emulate_tas": EnumSetting("emulate_tas", [0, 1], 1),
    "emulate_tpu": EnumSetting("emulate_tpu", [0, 1], 0),
    "emulate_tpws": EnumSetting("emulate_tpws", [0, 1], 0),
    "emulate_ua_intlck_ctrl": EnumSetting("emulate_ua_intlck_ctrl", [0, 1, 2], 0),
    "emulate_write_cache": EnumSetting("emulate_write_cache", [0, 1], 0),
    "enforce_pr_isids": EnumSetting("enforce_pr_isids", [0, 1], 1),
    "force_pr_aptpl": EnumSetting("force_pr_aptpl", [0, 1], 0),
    "is_nonrot": EnumSetting("is_nonrot", [0, 1], 1),
    "max_unmap_block_desc_count": IntSetting("max_unmap_block_desc_count", 0, 4294967295, 1),
    "max_unmap_lba_count": IntSetting("max_unmap_lba_count", 0, 4294967295, 8192),
    "max_write_same_len": IntSetting("max_write_same_len", 0, 4294967295, 65535),
    "optimal_sectors": IntSetting("optimal_sectors", 0, 4294967295, 8192),
    "pi_prot_type": EnumSetting("pi_prot_type", [0, 1, 2, 3], 0),
    "pi_prot_verify": EnumSetting("pi_prot_verify", [0, 1], 0),
    "queue_depth": IntSetting("queue_depth", 0, 4294967295, 256),
    "unmap_granularity": IntSetting("unmap_granularity", 0, 4294967295, 8192),
    "unmap_granularity_alignment": IntSetting("unmap_granularity_alignment", 0, 4294967295, 0),
    "unmap_zeroes_data": EnumSetting("unmap_zeroes_data", [0, 1], 0)}
