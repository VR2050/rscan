package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class AndroidRoomsConfig {
    private final boolean isRooms;

    public AndroidRoomsConfig(boolean isRooms) {
        this.isRooms = isRooms;
    }

    public boolean isRooms() {
        return this.isRooms;
    }

    static AndroidRoomsConfig create(boolean isRooms) {
        return new AndroidRoomsConfig(isRooms);
    }
}
