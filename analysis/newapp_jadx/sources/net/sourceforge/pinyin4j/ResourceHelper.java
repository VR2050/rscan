package net.sourceforge.pinyin4j;

import java.io.BufferedInputStream;

/* loaded from: classes3.dex */
public class ResourceHelper {
    public static BufferedInputStream getResourceInputStream(String str) {
        return new BufferedInputStream(ResourceHelper.class.getResourceAsStream(str));
    }
}
