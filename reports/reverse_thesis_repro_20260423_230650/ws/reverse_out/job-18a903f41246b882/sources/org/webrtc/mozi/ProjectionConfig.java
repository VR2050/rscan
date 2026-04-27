package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class ProjectionConfig {
    private final boolean androidForceHwEncoder;
    private final boolean isMeetingProjection;
    private final boolean isP2pProjection;

    public ProjectionConfig(boolean isP2pProjection, boolean isMeetingProjection, boolean androidForceHwEncoder) {
        this.isP2pProjection = isP2pProjection;
        this.isMeetingProjection = isMeetingProjection;
        this.androidForceHwEncoder = androidForceHwEncoder;
    }

    public boolean isP2pProjection() {
        return this.isP2pProjection;
    }

    public boolean isMeetingProjection() {
        return this.isMeetingProjection;
    }

    public boolean androidForceHwEncoder() {
        return this.androidForceHwEncoder;
    }

    static ProjectionConfig create(boolean isP2pProjection, boolean isMeetingProjection, boolean androidForceHwEncoder) {
        return new ProjectionConfig(isP2pProjection, isMeetingProjection, androidForceHwEncoder);
    }
}
