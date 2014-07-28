package de.datawerk.cordova.plugin.data;

import org.json.JSONException;
import org.json.JSONObject;

public class SimpleDataProgressResult {

    private long loaded = 0;
    private long total = 0;

    public long getLoaded() {
        return loaded;
    }

    public void setLoaded(long bytes) {
        this.loaded = bytes;
    }

    public long getTotal() {
        return total;
    }

    public void setTotal(long bytes) {
        this.total = bytes;
    }

    public JSONObject toJSONObject() throws JSONException {
        return new JSONObject(
                "{loaded:" + loaded +
                ",total:" + total +
                "}");
    }
}
