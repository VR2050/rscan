package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogSexBinding implements ViewBinding {

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvSexCanel;

    @NonNull
    public final TextView tvSexFemale;

    @NonNull
    public final TextView tvSexMale;

    @NonNull
    public final TextView tvSexPrivate;

    private DialogSexBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = linearLayout;
        this.tvSexCanel = textView;
        this.tvSexFemale = textView2;
        this.tvSexMale = textView3;
        this.tvSexPrivate = textView4;
    }

    @NonNull
    public static DialogSexBinding bind(@NonNull View view) {
        int i2 = R.id.tv_sex_canel;
        TextView textView = (TextView) view.findViewById(R.id.tv_sex_canel);
        if (textView != null) {
            i2 = R.id.tv_sex_female;
            TextView textView2 = (TextView) view.findViewById(R.id.tv_sex_female);
            if (textView2 != null) {
                i2 = R.id.tv_sex_male;
                TextView textView3 = (TextView) view.findViewById(R.id.tv_sex_male);
                if (textView3 != null) {
                    i2 = R.id.tv_sex_private;
                    TextView textView4 = (TextView) view.findViewById(R.id.tv_sex_private);
                    if (textView4 != null) {
                        return new DialogSexBinding((LinearLayout) view, textView, textView2, textView3, textView4);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogSexBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogSexBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_sex, viewGroup, false);
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
