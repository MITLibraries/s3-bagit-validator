-- union all CDPS inventory tables
with cdps_aip_inventory as (
    select * from "aip1b-data"
    union all select * from "aip2b-data"
    union all select * from "aip3b-data"
    union all select * from "aip4b-data"
    union all select * from "aip5b-data"
)
select
    parse_datetime(dt, 'yyyy-MM-dd-HH-mm') as s3_inventory_date,
    from_unixtime(last_modified_date / 1000) as last_modified,
    key,
    checksum_algorithm
from cdps_aip_inventory as cai

-- ensures data is coming from last S3 inventory pull parquet file(s)
where dt = (select max(dt) as dt from cdps_aip_inventory)

-- ensures data is only for most recent form of record and not deleted
and is_latest
and not is_delete_marker

-- lastly, filter to our AIP prefix
and key like %(s3_key_prefix)s
;