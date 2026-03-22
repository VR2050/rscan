package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.page.MyViewPager;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActAudioPageBinding implements ViewBinding {

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final MyViewPager vpContent;

    private ActAudioPageBinding(@NonNull LinearLayout linearLayout, @NonNull MyViewPager myViewPager) {
        this.rootView = linearLayout;
        this.vpContent = myViewPager;
    }

    @NonNull
    public static ActAudioPageBinding bind(@NonNull View view) {
        MyViewPager myViewPager = (MyViewPager) view.findViewById(R.id.vp_content);
        if (myViewPager != null) {
            return new ActAudioPageBinding((LinearLayout) view, myViewPager);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.vp_content)));
    }

    @NonNull
    public static ActAudioPageBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActAudioPageBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_audio_page, viewGroup, false);
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
