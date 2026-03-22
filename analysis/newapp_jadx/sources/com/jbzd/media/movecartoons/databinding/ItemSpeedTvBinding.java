package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.noober.background.view.BLTextView;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class ItemSpeedTvBinding implements ViewBinding {

    @NonNull
    private final BLTextView rootView;

    /* renamed from: tv */
    @NonNull
    public final BLTextView f10057tv;

    private ItemSpeedTvBinding(@NonNull BLTextView bLTextView, @NonNull BLTextView bLTextView2) {
        this.rootView = bLTextView;
        this.f10057tv = bLTextView2;
    }

    @NonNull
    public static ItemSpeedTvBinding bind(@NonNull View view) {
        Objects.requireNonNull(view, "rootView");
        BLTextView bLTextView = (BLTextView) view;
        return new ItemSpeedTvBinding(bLTextView, bLTextView);
    }

    @NonNull
    public static ItemSpeedTvBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemSpeedTvBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_speed_tv, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public BLTextView getRoot() {
        return this.rootView;
    }
}
