package androidx.camera.view;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class FlashModeConverter {
    private FlashModeConverter() {
    }

    @NonNull
    public static String nameOf(int i2) {
        if (i2 == 0) {
            return "AUTO";
        }
        if (i2 == 1) {
            return "ON";
        }
        if (i2 == 2) {
            return "OFF";
        }
        throw new IllegalArgumentException(C1499a.m626l("Unknown flash mode ", i2));
    }

    public static int valueOf(@Nullable String str) {
        Objects.requireNonNull(str, "name cannot be null");
        str.hashCode();
        switch (str) {
            case "ON":
                return 1;
            case "OFF":
                return 2;
            case "AUTO":
                return 0;
            default:
                throw new IllegalArgumentException(C1499a.m637w("Unknown flash mode name ", str));
        }
    }
}
