package io.openinstall.sdk;

/* JADX INFO: loaded from: classes3.dex */
public enum dz {
    event_name_invalid("传入的效果点名称包含不支持的字符 %s", "The provided event name contains unsupported characters %s"),
    event_extra_larger("传入的效果点附加参数超过限制", "The provided extra data is too large"),
    init_background("疑似应用处于后台不可见状态下调用init，并且接着调用其它api，数据大概率丢失，请检查代码", "Calling start while the application is in the background may fail to fetch the data"),
    getting_data("获取到 %s", "Getting the data: %s");

    private final String e;
    private final String f;

    dz(String str, String str2) {
        this.e = str;
        this.f = str2;
    }

    public String a() {
        return as.a().b() ? this.f : this.e;
    }
}
