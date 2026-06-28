#!/usr/bin/env python3
"""
Generate a Kibana saved-objects NDJSON file containing a full SOC dashboard
(visualizations + dashboard) built on the django-alerts* and django-responses*
data views. Output is imported via the Kibana saved_objects/_import API.

Re-runnable: all objects use stable IDs, imported with overwrite=true.
"""
import json

ALERTS_DV = "38e5ba94-a9de-4d48-98fd-333035fcc0f2"   # django-alerts*
RESP_DV   = "2ec1ce58-69ac-4771-8528-39bb46a357a7"   # django-responses*

objs = []


def search_source(kql=""):
    return json.dumps({
        "query": {"query": kql, "language": "kuery"},
        "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    })


def viz(vid, title, vis_state, dv_id, kql=""):
    objs.append({
        "id": vid,
        "type": "visualization",
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(kql)},
        },
        "references": [{
            "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
            "type": "index-pattern", "id": dv_id,
        }],
    })


# ---------- visualization builders ----------
def metric(vid, title, dv, kql="", agg_type="count", field=None, color="#3185FC"):
    agg = {"id": "1", "enabled": True, "type": agg_type, "schema": "metric",
           "params": ({"field": field} if field else {})}
    state = {
        "title": title, "type": "metric",
        "aggs": [agg],
        "params": {"addTooltip": True, "addLegend": False, "type": "metric",
                   "metric": {"percentageMode": False, "useRanges": False,
                              "colorSchema": "Green to Red", "metricColorMode": "None",
                              "colorsRange": [{"from": 0, "to": 10000}],
                              "labels": {"show": True},
                              "invertColors": False,
                              "style": {"bgFill": color, "bgColor": True, "labelColor": False,
                                        "subText": "", "fontSize": 40}}},
    }
    viz(vid, title, state, dv, kql)


def pie(vid, title, dv, field, size=10, kql="", donut=True):
    state = {
        "title": title, "type": "pie",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": field, "size": size, "order": "desc", "orderBy": "1",
                        "otherBucket": False, "missingBucket": False}},
        ],
        "params": {"type": "pie", "addTooltip": True, "addLegend": True,
                   "legendPosition": "right", "isDonut": donut,
                   "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}},
    }
    viz(vid, title, state, dv, kql)


def table(vid, title, dv, field, size=10, kql="", metric_agg="count", metric_field=None):
    metric = {"id": "1", "enabled": True, "type": metric_agg, "schema": "metric",
              "params": ({"field": metric_field} if metric_field else {})}
    state = {
        "title": title, "type": "table",
        "aggs": [
            metric,
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
             "params": {"field": field, "size": size, "order": "desc", "orderBy": "1"}},
        ],
        "params": {"perPage": size, "showPartialRows": False, "showMetricsAtAllLevels": False,
                   "showTotal": False, "totalFunc": "sum", "percentageCol": ""},
    }
    viz(vid, title, state, dv, kql)


def _axes(label="Count"):
    return {
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                          "show": True, "scale": {"type": "linear"},
                          "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left",
                       "show": True, "scale": {"type": "linear", "mode": "normal"},
                       "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                       "title": {"text": label}}],
    }


def time_series(vid, title, dv, date_field, split_field=None, kql="", chart="area"):
    aggs = [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": date_field, "useNormalizedEsInterval": True, "interval": "auto",
                    "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}},
    ]
    if split_field:
        aggs.append({"id": "3", "enabled": True, "type": "terms", "schema": "group",
                     "params": {"field": split_field, "size": 8, "order": "desc", "orderBy": "1"}})
    params = {"type": chart,
              "grid": {"categoryLines": False},
              **_axes(),
              "seriesParams": [{"show": True, "type": chart, "mode": "stacked",
                                "data": {"label": "Count", "id": "1"},
                                "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                                "lineWidth": 2, "showCircles": True, "interpolate": "linear"}],
              "addTooltip": True, "addLegend": True, "legendPosition": "right",
              "times": [], "addTimeMarker": False,
              "labels": {"show": False},
              "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}}
    state = {"title": title, "type": chart, "aggs": aggs, "params": params}
    viz(vid, title, state, dv, kql)


def hbar(vid, title, dv, field, size=10, kql=""):
    state = {
        "title": title, "type": "horizontal_bar",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": field, "size": size, "order": "desc", "orderBy": "1"}},
        ],
        "params": {"type": "horizontal_bar", "grid": {"categoryLines": False},
                   "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "left",
                                     "show": True, "scale": {"type": "linear"},
                                     "labels": {"show": True, "filter": False, "truncate": 200}, "title": {}}],
                   "valueAxes": [{"id": "ValueAxis-1", "name": "BottomAxis-1", "type": "value",
                                  "position": "bottom", "show": True,
                                  "scale": {"type": "linear", "mode": "normal"},
                                  "labels": {"show": True, "rotate": 75, "filter": True, "truncate": 100},
                                  "title": {"text": "Count"}}],
                   "seriesParams": [{"show": True, "type": "histogram", "mode": "normal",
                                     "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
                                     "drawLinesBetweenPoints": True, "showCircles": True}],
                   "addTooltip": True, "addLegend": True, "legendPosition": "right",
                   "times": [], "addTimeMarker": False, "labels": {"show": False}},
    }
    viz(vid, title, state, dv, kql)


# ---------- the panels ----------
# Row of KPI metric tiles
metric("siem-m-total-alerts",  "Total Alerts",        ALERTS_DV, color="#3185FC")
metric("siem-m-crit-high",     "Critical / High",     ALERTS_DV, kql='severity:("critical" or "high")', color="#BD271E")
metric("siem-m-unique-ips",    "Unique Source IPs",   ALERTS_DV, agg_type="cardinality", field="source_ip", color="#F5A700")
metric("siem-m-unresolved",    "Unresolved Alerts",   ALERTS_DV, kql='not status:"resolved"', color="#CA8EAE")
metric("siem-m-blocks",        "IPs Blocked",         RESP_DV,   kql='action_type:"block_ip" and status:"executed"', color="#017D73")
metric("siem-m-failed-resp",   "Failed Responses",    RESP_DV,   kql='status:"failed"', color="#DD0A73")

# Time + distribution
time_series("siem-ts-alerts",  "Alerts Over Time (by severity)", ALERTS_DV, "timestamp", split_field="severity", chart="area")
pie("siem-pie-severity",       "Alerts by Severity",  ALERTS_DV, "severity", donut=True)
pie("siem-pie-attack",         "Alerts by Attack Type", ALERTS_DV, "attack_type", donut=True)
pie("siem-pie-status",         "Alert Status",        ALERTS_DV, "status", donut=True)

# Top offenders / rules
table("siem-tbl-ips",          "Top Source IPs",      ALERTS_DV, "source_ip", size=10)
hbar("siem-bar-rules",         "Top Triggered Rules", ALERTS_DV, "rule_description.keyword", size=10)

# Responses analytics
pie("siem-pie-action",         "Responses by Action Type", RESP_DV, "action_type", donut=True)
pie("siem-pie-respstatus",     "Response Outcomes",   RESP_DV, "status", donut=True)
time_series("siem-ts-resp",    "Responses Over Time (by action)", RESP_DV, "created_at", split_field="action_type", chart="histogram")
table("siem-tbl-targets",      "Top Response Targets", RESP_DV, "target", size=10)
pie("siem-pie-trigger",        "Auto vs Manual Trigger", RESP_DV, "trigger", donut=True)

# ---------- dashboard layout (48-col grid) ----------
panels = [
    # KPI row (y=0,h=8)
    ("siem-m-total-alerts",  0,  0,  8, 8),
    ("siem-m-crit-high",     8,  0,  8, 8),
    ("siem-m-unique-ips",    16, 0,  8, 8),
    ("siem-m-unresolved",    24, 0,  8, 8),
    ("siem-m-blocks",        32, 0,  8, 8),
    ("siem-m-failed-resp",   40, 0,  8, 8),
    # time + severity (y=8,h=15)
    ("siem-ts-alerts",       0,  8,  32, 15),
    ("siem-pie-severity",    32, 8,  16, 15),
    # distributions (y=23,h=15)
    ("siem-pie-attack",      0,  23, 16, 15),
    ("siem-pie-status",      16, 23, 16, 15),
    ("siem-pie-action",      32, 23, 16, 15),
    # offenders/rules (y=38,h=15)
    ("siem-tbl-ips",         0,  38, 24, 15),
    ("siem-bar-rules",       24, 38, 24, 15),
    # responses (y=53,h=15)
    ("siem-ts-resp",         0,  53, 32, 15),
    ("siem-pie-respstatus",  32, 53, 16, 15),
    # responses 2 (y=68,h=15)
    ("siem-tbl-targets",     0,  68, 24, 15),
    ("siem-pie-trigger",     24, 68, 24, 15),
]

panels_json, refs = [], []
for i, (vid, x, y, w, h) in enumerate(panels):
    pref = f"panel_{i}"
    panels_json.append({
        "version": "8.15.3",
        "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
        "panelIndex": str(i),
        "embeddableConfig": {"enhancements": {}},
        "panelRefName": pref,
    })
    refs.append({"name": pref, "type": "visualization", "id": vid})

dashboard = {
    "id": "siem-soc-overview",
    "type": "dashboard",
    "attributes": {
        "title": "SIEM — SOC Overview",
        "description": "Attacks detected by Wazuh and automated responses taken by Django.",
        "panelsJSON": json.dumps(panels_json),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
        "version": 1,
        "timeRestore": True,
        "timeTo": "now",
        "timeFrom": "now-30d",
        "refreshInterval": {"pause": False, "value": 30000},
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
        },
    },
    "references": refs,
}
objs.append(dashboard)

with open("/home/hazem/automated_incident_response/kibana/soc-dashboard.ndjson", "w") as f:
    for o in objs:
        f.write(json.dumps(o) + "\n")

print(f"Wrote {len(objs)} objects ({len(panels)} panels + 1 dashboard) to soc-dashboard.ndjson")
