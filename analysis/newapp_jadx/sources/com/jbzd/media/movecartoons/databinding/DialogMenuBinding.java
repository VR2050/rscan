package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogMenuBinding implements ViewBinding {

    @NonNull
    public final FrameLayout btnExit;

    @NonNull
    public final FrameLayout btnRecharge;

    @NonNull
    public final FrameLayout btnRest;

    @NonNull
    private final FrameLayout rootView;

    private DialogMenuBinding(@NonNull FrameLayout frameLayout, @NonNull FrameLayout frameLayout2, @NonNull FrameLayout frameLayout3, @NonNull FrameLayout frameLayout4) {
        this.rootView = frameLayout;
        this.btnExit = frameLayout2;
        this.btnRecharge = frameLayout3;
        this.btnRest = frameLayout4;
    }

    @NonNull
    public static DialogMenuBinding bind(@NonNull View view) {
        int i2 = R.id.btnExit;
        FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.btnExit);
        if (frameLayout != null) {
            i2 = R.id.btnRecharge;
            FrameLayout frameLayout2 = (FrameLayout) view.findViewById(R.id.btnRecharge);
            if (frameLayout2 != null) {
                i2 = R.id.btnRest;
                FrameLayout frameLayout3 = (FrameLayout) view.findViewById(R.id.btnRest);
                if (frameLayout3 != null) {
                    return new DialogMenuBinding((FrameLayout) view, frameLayout, frameLayout2, frameLayout3);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogMenuBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogMenuBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_menu, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public FrameLayout getRoot() {
        return this.rootView;
    }
}
