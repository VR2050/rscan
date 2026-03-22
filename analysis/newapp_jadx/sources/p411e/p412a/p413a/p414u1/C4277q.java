package p411e.p412a.p413a.p414u1;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.impl.Config;
import androidx.camera.core.impl.MutableOptionsBundle;
import androidx.camera.core.impl.OptionsBundle;

/* renamed from: e.a.a.u1.q */
/* loaded from: classes.dex */
public final /* synthetic */ class C4277q {
    @NonNull
    /* renamed from: a */
    public static Config m4852a(@Nullable Config config, @Nullable Config config2) {
        if (config == null && config2 == null) {
            return OptionsBundle.emptyBundle();
        }
        MutableOptionsBundle from = config2 != null ? MutableOptionsBundle.from(config2) : MutableOptionsBundle.create();
        if (config != null) {
            for (Config.Option<?> option : config.listOptions()) {
                from.insertOption(option, config.getOptionPriority(option), config.retrieveOption(option));
            }
        }
        return OptionsBundle.from(from);
    }
}
