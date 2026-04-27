package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class HardwareModel {
    private final String codec;
    private final String name;
    private final String version;

    public HardwareModel(String codec, String name, String version) {
        this.codec = codec;
        this.name = name;
        this.version = version;
    }

    public String getCodec() {
        return this.codec;
    }

    public String getName() {
        return this.name;
    }

    public String getVersion() {
        return this.version;
    }

    static HardwareModel create(String codec, String name, String version) {
        return new HardwareModel(codec, name, version);
    }
}
