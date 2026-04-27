package com.google.android.exoplayer2.offline;

import android.net.Uri;
import com.google.android.exoplayer2.util.Assertions;
import com.google.android.exoplayer2.util.Util;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public final class DownloadAction {
    public static final String TYPE_DASH = "dash";
    public static final String TYPE_HLS = "hls";
    public static final String TYPE_PROGRESSIVE = "progressive";
    public static final String TYPE_SS = "ss";
    private static final int VERSION = 2;
    public final String customCacheKey;
    public final byte[] data;
    public final String id;
    public final boolean isRemoveAction;
    public final List<StreamKey> keys;
    public final String type;
    public final Uri uri;

    public static DownloadAction fromByteArray(byte[] data) throws IOException {
        ByteArrayInputStream input = new ByteArrayInputStream(data);
        return deserializeFromStream(input);
    }

    public static DownloadAction deserializeFromStream(InputStream input) throws IOException {
        return readFromStream(new DataInputStream(input));
    }

    public static DownloadAction createDownloadAction(String type, Uri uri, List<StreamKey> keys, String customCacheKey, byte[] data) {
        return new DownloadAction(type, uri, false, keys, customCacheKey, data);
    }

    public static DownloadAction createRemoveAction(String type, Uri uri, String customCacheKey) {
        return new DownloadAction(type, uri, true, Collections.emptyList(), customCacheKey, null);
    }

    private DownloadAction(String type, Uri uri, boolean isRemoveAction, List<StreamKey> keys, String customCacheKey, byte[] data) {
        this.id = customCacheKey != null ? customCacheKey : uri.toString();
        this.type = type;
        this.uri = uri;
        this.isRemoveAction = isRemoveAction;
        this.customCacheKey = customCacheKey;
        if (isRemoveAction) {
            Assertions.checkArgument(keys.isEmpty());
            Assertions.checkArgument(data == null);
            this.keys = Collections.emptyList();
            this.data = Util.EMPTY_BYTE_ARRAY;
            return;
        }
        ArrayList<StreamKey> mutableKeys = new ArrayList<>(keys);
        Collections.sort(mutableKeys);
        this.keys = Collections.unmodifiableList(mutableKeys);
        this.data = data != null ? Arrays.copyOf(data, data.length) : Util.EMPTY_BYTE_ARRAY;
    }

    public byte[] toByteArray() {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            serializeToStream(output);
            return output.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException();
        }
    }

    public boolean isSameMedia(DownloadAction other) {
        return this.id.equals(other.id);
    }

    public List<StreamKey> getKeys() {
        return this.keys;
    }

    public boolean equals(Object o) {
        if (!(o instanceof DownloadAction)) {
            return false;
        }
        DownloadAction that = (DownloadAction) o;
        return this.id.equals(that.id) && this.type.equals(that.type) && this.uri.equals(that.uri) && this.isRemoveAction == that.isRemoveAction && this.keys.equals(that.keys) && Util.areEqual(this.customCacheKey, that.customCacheKey) && Arrays.equals(this.data, that.data);
    }

    public final int hashCode() {
        int iHashCode = ((((((((this.type.hashCode() * 31) + this.id.hashCode()) * 31) + this.uri.hashCode()) * 31) + (this.isRemoveAction ? 1 : 0)) * 31) + this.keys.hashCode()) * 31;
        String str = this.customCacheKey;
        return ((iHashCode + (str != null ? str.hashCode() : 0)) * 31) + Arrays.hashCode(this.data);
    }

    public final void serializeToStream(OutputStream output) throws IOException {
        DataOutputStream dataOutputStream = new DataOutputStream(output);
        dataOutputStream.writeUTF(this.type);
        dataOutputStream.writeInt(2);
        dataOutputStream.writeUTF(this.uri.toString());
        dataOutputStream.writeBoolean(this.isRemoveAction);
        dataOutputStream.writeInt(this.data.length);
        dataOutputStream.write(this.data);
        dataOutputStream.writeInt(this.keys.size());
        for (int i = 0; i < this.keys.size(); i++) {
            StreamKey key = this.keys.get(i);
            dataOutputStream.writeInt(key.periodIndex);
            dataOutputStream.writeInt(key.groupIndex);
            dataOutputStream.writeInt(key.trackIndex);
        }
        dataOutputStream.writeBoolean(this.customCacheKey != null);
        String str = this.customCacheKey;
        if (str != null) {
            dataOutputStream.writeUTF(str);
        }
        dataOutputStream.flush();
    }

    private static DownloadAction readFromStream(DataInputStream input) throws IOException {
        byte[] data;
        String customCacheKey;
        String type = input.readUTF();
        int version = input.readInt();
        Uri uri = Uri.parse(input.readUTF());
        boolean isRemoveAction = input.readBoolean();
        int dataLength = input.readInt();
        if (dataLength != 0) {
            byte[] data2 = new byte[dataLength];
            input.readFully(data2);
            if (!isRemoveAction) {
                data = data2;
            } else {
                data = null;
            }
        } else {
            data = null;
        }
        boolean z = false;
        boolean isLegacyProgressive = version == 0 && TYPE_PROGRESSIVE.equals(type);
        List<StreamKey> keys = new ArrayList<>();
        if (!isLegacyProgressive) {
            int keyCount = input.readInt();
            for (int i = 0; i < keyCount; i++) {
                keys.add(readKey(type, version, input));
            }
        }
        if (version < 2 && (TYPE_DASH.equals(type) || TYPE_HLS.equals(type) || TYPE_SS.equals(type))) {
            z = true;
        }
        boolean isLegacySegmented = z;
        if (isLegacySegmented) {
            customCacheKey = null;
        } else {
            String customCacheKey2 = input.readBoolean() ? input.readUTF() : null;
            customCacheKey = customCacheKey2;
        }
        return new DownloadAction(type, uri, isRemoveAction, keys, customCacheKey, data);
    }

    private static StreamKey readKey(String type, int version, DataInputStream input) throws IOException {
        int periodIndex;
        int groupIndex;
        int trackIndex;
        if ((TYPE_HLS.equals(type) || TYPE_SS.equals(type)) && version == 0) {
            periodIndex = 0;
            groupIndex = input.readInt();
            trackIndex = input.readInt();
        } else {
            periodIndex = input.readInt();
            groupIndex = input.readInt();
            trackIndex = input.readInt();
        }
        return new StreamKey(periodIndex, groupIndex, trackIndex);
    }
}
