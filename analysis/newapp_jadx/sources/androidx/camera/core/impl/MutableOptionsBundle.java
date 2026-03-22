package androidx.camera.core.impl;

import android.util.ArrayMap;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.camera.core.impl.Config;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class MutableOptionsBundle extends OptionsBundle implements MutableConfig {

    @NonNull
    private static final Config.OptionPriority DEFAULT_PRIORITY = Config.OptionPriority.OPTIONAL;

    private MutableOptionsBundle(TreeMap<Config.Option<?>, Map<Config.OptionPriority, Object>> treeMap) {
        super(treeMap);
    }

    @NonNull
    public static MutableOptionsBundle create() {
        return new MutableOptionsBundle(new TreeMap(OptionsBundle.ID_COMPARE));
    }

    @NonNull
    public static MutableOptionsBundle from(@NonNull Config config) {
        TreeMap treeMap = new TreeMap(OptionsBundle.ID_COMPARE);
        for (Config.Option<?> option : config.listOptions()) {
            Set<Config.OptionPriority> priorities = config.getPriorities(option);
            ArrayMap arrayMap = new ArrayMap();
            for (Config.OptionPriority optionPriority : priorities) {
                arrayMap.put(optionPriority, config.retrieveOptionWithPriority(option, optionPriority));
            }
            treeMap.put(option, arrayMap);
        }
        return new MutableOptionsBundle(treeMap);
    }

    @Override // androidx.camera.core.impl.MutableConfig
    public <ValueT> void insertOption(@NonNull Config.Option<ValueT> option, @Nullable ValueT valuet) {
        insertOption(option, DEFAULT_PRIORITY, valuet);
    }

    @Override // androidx.camera.core.impl.MutableConfig
    @Nullable
    public <ValueT> ValueT removeOption(@NonNull Config.Option<ValueT> option) {
        return (ValueT) this.mOptions.remove(option);
    }

    @Override // androidx.camera.core.impl.MutableConfig
    public <ValueT> void insertOption(@NonNull Config.Option<ValueT> option, @NonNull Config.OptionPriority optionPriority, @Nullable ValueT valuet) {
        Config.OptionPriority optionPriority2;
        Map<Config.OptionPriority, Object> map = this.mOptions.get(option);
        if (map == null) {
            ArrayMap arrayMap = new ArrayMap();
            this.mOptions.put(option, arrayMap);
            arrayMap.put(optionPriority, valuet);
            return;
        }
        Config.OptionPriority optionPriority3 = (Config.OptionPriority) Collections.min(map.keySet());
        if (!map.get(optionPriority3).equals(valuet)) {
            Config.OptionPriority optionPriority4 = Config.OptionPriority.ALWAYS_OVERRIDE;
            boolean z = true;
            if ((optionPriority3 != optionPriority4 || optionPriority != optionPriority4) && (optionPriority3 != (optionPriority2 = Config.OptionPriority.REQUIRED) || optionPriority != optionPriority2)) {
                z = false;
            }
            if (z) {
                StringBuilder m586H = C1499a.m586H("Option values conflicts: ");
                m586H.append(option.getId());
                m586H.append(", existing value (");
                m586H.append(optionPriority3);
                m586H.append(")=");
                m586H.append(map.get(optionPriority3));
                m586H.append(", conflicting (");
                m586H.append(optionPriority);
                m586H.append(")=");
                m586H.append(valuet);
                throw new IllegalArgumentException(m586H.toString());
            }
        }
        map.put(optionPriority, valuet);
    }
}
