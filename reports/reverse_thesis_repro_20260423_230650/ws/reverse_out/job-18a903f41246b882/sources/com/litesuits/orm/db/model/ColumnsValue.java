package com.litesuits.orm.db.model;

import com.litesuits.orm.db.assit.Checker;
import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes3.dex */
public class ColumnsValue {
    public String[] columns;
    private Map<String, Object> map;

    public ColumnsValue(Map<String, Object> map) {
        this.map = new HashMap();
        if (!Checker.isEmpty(map)) {
            this.columns = new String[map.size()];
            int i = 0;
            for (Map.Entry<String, Object> entry : map.entrySet()) {
                this.columns[i] = entry.getKey();
                i++;
            }
            this.map = map;
        }
    }

    public ColumnsValue(String[] columns) {
        this.map = new HashMap();
        this.columns = columns;
        for (String key : columns) {
            this.map.put(key, null);
        }
    }

    public ColumnsValue(String[] columns, Object[] values) {
        this.map = new HashMap();
        this.columns = columns;
        if (values != null) {
            if (columns.length != values.length) {
                throw new IllegalArgumentException("length of columns and values must be the same");
            }
            int i = 0;
            int len$ = columns.length;
            int i$ = 0;
            while (i$ < len$) {
                String key = columns[i$];
                this.map.put(key, values[i]);
                i$++;
                i++;
            }
            return;
        }
        for (String key2 : columns) {
            this.map.put(key2, null);
        }
    }

    public boolean checkColumns() {
        if (this.columns == null) {
            throw new IllegalArgumentException("columns must not be null");
        }
        return true;
    }

    public Object getValue(String key) {
        return this.map.get(key);
    }
}
