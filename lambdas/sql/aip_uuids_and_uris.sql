/*
Parse AIP UUIDs from their S3 keys and provide file counts for each.  This provides
enough data to locate the s3 bucket + key for a given AIP UUID.
*/

with cdps_aip_inventory_timeseries as (
    select * from "aip1b-data" where dt = (select max(dt) from "aip1b-data")
    union all select * from "aip2b-data" where dt = (select max(dt) from "aip2b-data")
    union all select * from "aip3b-data" where dt = (select max(dt) from "aip3b-data")
    union all select * from "aip4b-data" where dt = (select max(dt) from "aip4b-data")
    union all select * from "aip5b-data" where dt = (select max(dt) from "aip5b-data")
),
cdps_aip_inventory as (
    select * from cdps_aip_inventory_timeseries
    where is_latest
    and not is_delete_marker
),
cdps_aip_inventory_with_aip_uuid as (
    select
        bucket,
        case
            when regexp_like(key, '.*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/.*)?$')
            then regexp_extract(key, '.*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/.*)?$', 1)
            else null
        end as aip_uuid,
        case
            when regexp_like(key, '.*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/.*)?$')
            then regexp_extract(key, '(.*?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 1)
            else null
        end as aip_s3_uri,
        key,
        size,
        last_modified_date
    from cdps_aip_inventory
)
select
    bucket,
    aip_uuid,
    aip_s3_uri,
    count(*) as aip_files_count,
    sum(size) as total_size_bytes,
    min(last_modified_date) as earliest_file_date,
    max(last_modified_date) as latest_file_date
from cdps_aip_inventory_with_aip_uuid
where aip_uuid is not null
group by bucket, aip_uuid, aip_s3_uri
order by count(*) desc;