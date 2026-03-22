package p411e.p412a.p413a.p414u1;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.impl.Config;
import androidx.camera.core.impl.ReadableConfig;
import java.util.Set;

/* renamed from: e.a.a.u1.t */
/* loaded from: classes.dex */
public final /* synthetic */ class C4280t {
    /* renamed from: a */
    public static boolean m4866a(@NonNull ReadableConfig _this, Config.Option option) {
        return _this.getConfig().containsOption(option);
    }

    /* renamed from: b */
    public static void m4867b(@NonNull ReadableConfig _this, @NonNull String str, Config.OptionMatcher optionMatcher) {
        _this.getConfig().findOptions(str, optionMatcher);
    }

    @NonNull
    /* renamed from: c */
    public static Config.OptionPriority m4868c(@NonNull ReadableConfig _this, Config.Option option) {
        return _this.getConfig().getOptionPriority(option);
    }

    @NonNull
    /* renamed from: d */
    public static Set m4869d(@NonNull ReadableConfig _this, Config.Option option) {
        return _this.getConfig().getPriorities(option);
    }

    @NonNull
    /* renamed from: e */
    public static Set m4870e(ReadableConfig _this) {
        return _this.getConfig().listOptions();
    }

    @Nullable
    /* renamed from: f */
    public static Object m4871f(@NonNull ReadableConfig _this, Config.Option option) {
        return _this.getConfig().retrieveOption(option);
    }

    @Nullable
    /* renamed from: g */
    public static Object m4872g(@NonNull ReadableConfig _this, @Nullable Config.Option option, Object obj) {
        return _this.getConfig().retrieveOption(option, obj);
    }

    @Nullable
    /* renamed from: h */
    public static Object m4873h(@NonNull ReadableConfig _this, @NonNull Config.Option option, Config.OptionPriority optionPriority) {
        return _this.getConfig().retrieveOptionWithPriority(option, optionPriority);
    }
}
