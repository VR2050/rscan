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
public final class ActCreaterApplyBinding implements ViewBinding {

    @NonNull
    public final TextView btnApply;

    @NonNull
    public final LinearLayout llCard;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvGrouplinkJoin;

    @NonNull
    public final TextView tvOfficialGmail;

    @NonNull
    public final TextView tvServiceLink;

    @NonNull
    public final TextView tvServiceemailCopy;

    @NonNull
    public final TextView tvServicelinkCopy;

    private ActCreaterApplyBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull LinearLayout linearLayout2, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6) {
        this.rootView = linearLayout;
        this.btnApply = textView;
        this.llCard = linearLayout2;
        this.tvGrouplinkJoin = textView2;
        this.tvOfficialGmail = textView3;
        this.tvServiceLink = textView4;
        this.tvServiceemailCopy = textView5;
        this.tvServicelinkCopy = textView6;
    }

    @NonNull
    public static ActCreaterApplyBinding bind(@NonNull View view) {
        int i2 = R.id.btn_apply;
        TextView textView = (TextView) view.findViewById(R.id.btn_apply);
        if (textView != null) {
            i2 = R.id.ll_card;
            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_card);
            if (linearLayout != null) {
                i2 = R.id.tv_grouplink_join;
                TextView textView2 = (TextView) view.findViewById(R.id.tv_grouplink_join);
                if (textView2 != null) {
                    i2 = R.id.tv_official_gmail;
                    TextView textView3 = (TextView) view.findViewById(R.id.tv_official_gmail);
                    if (textView3 != null) {
                        i2 = R.id.tv_service_link;
                        TextView textView4 = (TextView) view.findViewById(R.id.tv_service_link);
                        if (textView4 != null) {
                            i2 = R.id.tv_serviceemail_copy;
                            TextView textView5 = (TextView) view.findViewById(R.id.tv_serviceemail_copy);
                            if (textView5 != null) {
                                i2 = R.id.tv_servicelink_copy;
                                TextView textView6 = (TextView) view.findViewById(R.id.tv_servicelink_copy);
                                if (textView6 != null) {
                                    return new ActCreaterApplyBinding((LinearLayout) view, textView, linearLayout, textView2, textView3, textView4, textView5, textView6);
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActCreaterApplyBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActCreaterApplyBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_creater_apply, viewGroup, false);
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
