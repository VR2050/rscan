package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class ItemDarkPlayDetailServiceBinding implements ViewBinding {

    @NonNull
    public final CheckBox cbService;

    @NonNull
    private final CheckBox rootView;

    private ItemDarkPlayDetailServiceBinding(@NonNull CheckBox checkBox, @NonNull CheckBox checkBox2) {
        this.rootView = checkBox;
        this.cbService = checkBox2;
    }

    @NonNull
    public static ItemDarkPlayDetailServiceBinding bind(@NonNull View view) {
        Objects.requireNonNull(view, "rootView");
        CheckBox checkBox = (CheckBox) view;
        return new ItemDarkPlayDetailServiceBinding(checkBox, checkBox);
    }

    @NonNull
    public static ItemDarkPlayDetailServiceBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemDarkPlayDetailServiceBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_dark_play_detail_service, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public CheckBox getRoot() {
        return this.rootView;
    }
}
