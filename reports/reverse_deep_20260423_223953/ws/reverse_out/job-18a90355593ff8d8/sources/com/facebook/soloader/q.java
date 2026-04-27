package com.facebook.soloader;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public class q {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public final String f8379a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public final List f8380b;

    q(String str, List list) {
        this.f8379a = str;
        this.f8380b = Collections.unmodifiableList(list);
    }

    public static q a(DataInputStream dataInputStream) throws IOException {
        String strC = c(dataInputStream);
        int i3 = dataInputStream.readShort() & 65535;
        ArrayList arrayList = new ArrayList();
        for (int i4 = 0; i4 < i3; i4++) {
            arrayList.add(d(dataInputStream));
        }
        return new q(strC, arrayList);
    }

    public static q b(InputStream inputStream) {
        return a(new DataInputStream(inputStream));
    }

    private static String c(DataInputStream dataInputStream) throws IOException {
        byte b3 = dataInputStream.readByte();
        if (b3 == 1) {
            return "arm64-v8a";
        }
        if (b3 == 2) {
            return "armeabi-v7a";
        }
        if (b3 == 3) {
            return "x86_64";
        }
        if (b3 == 4) {
            return "x86";
        }
        throw new RuntimeException("Unrecognized arch id: " + ((int) b3));
    }

    private static String d(DataInputStream dataInputStream) throws IOException {
        byte[] bArr = new byte[dataInputStream.readShort() & 65535];
        dataInputStream.readFully(bArr);
        return new String(bArr, StandardCharsets.UTF_8);
    }
}
