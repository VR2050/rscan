package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActWorksManagerBinding implements ViewBinding {

    @NonNull
    public final FrameLayout fragContent;

    @NonNull
    public final ImageTextView itvAll;

    @NonNull
    public final ImageTextView itvLong;

    @NonNull
    public final ImageTextView itvShort;

    @NonNull
    public final ImageTextView itvStatus;

    @NonNull
    private final LinearLayout rootView;

    private ActWorksManagerBinding(@NonNull LinearLayout linearLayout, @NonNull FrameLayout frameLayout, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull ImageTextView imageTextView3, @NonNull ImageTextView imageTextView4) {
        this.rootView = linearLayout;
        this.fragContent = frameLayout;
        this.itvAll = imageTextView;
        this.itvLong = imageTextView2;
        this.itvShort = imageTextView3;
        this.itvStatus = imageTextView4;
    }

    @NonNull
    public static ActWorksManagerBinding bind(@NonNull View view) {
        int i2 = R.id.frag_content;
        FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frag_content);
        if (frameLayout != null) {
            i2 = R.id.itv_all;
            ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_all);
            if (imageTextView != null) {
                i2 = R.id.itv_long;
                ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.itv_long);
                if (imageTextView2 != null) {
                    i2 = R.id.itv_short;
                    ImageTextView imageTextView3 = (ImageTextView) view.findViewById(R.id.itv_short);
                    if (imageTextView3 != null) {
                        i2 = R.id.itv_status;
                        ImageTextView imageTextView4 = (ImageTextView) view.findViewById(R.id.itv_status);
                        if (imageTextView4 != null) {
                            return new ActWorksManagerBinding((LinearLayout) view, frameLayout, imageTextView, imageTextView2, imageTextView3, imageTextView4);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActWorksManagerBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActWorksManagerBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_works_manager, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public LinearLayout getRoot() {
        return this.rootView;
    }
}
