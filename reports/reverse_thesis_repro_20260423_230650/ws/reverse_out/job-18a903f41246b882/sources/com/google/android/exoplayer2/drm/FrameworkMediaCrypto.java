package com.google.android.exoplayer2.drm;

import java.util.UUID;

/* JADX INFO: loaded from: classes2.dex */
public final class FrameworkMediaCrypto implements ExoMediaCrypto {
    public final boolean forceAllowInsecureDecoderComponents;
    public final byte[] sessionId;
    public final UUID uuid;

    public FrameworkMediaCrypto(UUID uuid, byte[] sessionId, boolean forceAllowInsecureDecoderComponents) {
        this.uuid = uuid;
        this.sessionId = sessionId;
        this.forceAllowInsecureDecoderComponents = forceAllowInsecureDecoderComponents;
    }
}
