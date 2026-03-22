package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogTimingBottomNightBinding implements ViewBinding {

    @NonNull
    public final TextView btn2Time;

    @NonNull
    public final TextView btn3Time;

    @NonNull
    public final TextView btn4Time;

    @NonNull
    public final TextView btn5Time;

    @NonNull
    public final ImageView close;

    @NonNull
    public final View outsideView;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView timingBtn1;

    @NonNull
    public final TextView timingBtn2;

    @NonNull
    public final TextView timingBtn3;

    @NonNull
    public final TextView timingBtn4;

    @NonNull
    public final TextView timingBtn5;

    private DialogTimingBottomNightBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull ImageView imageView, @NonNull View view, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull TextView textView7, @NonNull TextView textView8, @NonNull TextView textView9) {
        this.rootView = linearLayout;
        this.btn2Time = textView;
        this.btn3Time = textView2;
        this.btn4Time = textView3;
        this.btn5Time = textView4;
        this.close = imageView;
        this.outsideView = view;
        this.timingBtn1 = textView5;
        this.timingBtn2 = textView6;
        this.timingBtn3 = textView7;
        this.timingBtn4 = textView8;
        this.timingBtn5 = textView9;
    }

    @NonNull
    public static DialogTimingBottomNightBinding bind(@NonNull View view) {
        int i2 = R.id.btn2_time;
        TextView textView = (TextView) view.findViewById(R.id.btn2_time);
        if (textView != null) {
            i2 = R.id.btn3_time;
            TextView textView2 = (TextView) view.findViewById(R.id.btn3_time);
            if (textView2 != null) {
                i2 = R.id.btn4_time;
                TextView textView3 = (TextView) view.findViewById(R.id.btn4_time);
                if (textView3 != null) {
                    i2 = R.id.btn5_time;
                    TextView textView4 = (TextView) view.findViewById(R.id.btn5_time);
                    if (textView4 != null) {
                        i2 = R.id.close;
                        ImageView imageView = (ImageView) view.findViewById(R.id.close);
                        if (imageView != null) {
                            i2 = R.id.outside_view;
                            View findViewById = view.findViewById(R.id.outside_view);
                            if (findViewById != null) {
                                i2 = R.id.timing_btn1;
                                TextView textView5 = (TextView) view.findViewById(R.id.timing_btn1);
                                if (textView5 != null) {
                                    i2 = R.id.timing_btn2;
                                    TextView textView6 = (TextView) view.findViewById(R.id.timing_btn2);
                                    if (textView6 != null) {
                                        i2 = R.id.timing_btn3;
                                        TextView textView7 = (TextView) view.findViewById(R.id.timing_btn3);
                                        if (textView7 != null) {
                                            i2 = R.id.timing_btn4;
                                            TextView textView8 = (TextView) view.findViewById(R.id.timing_btn4);
                                            if (textView8 != null) {
                                                i2 = R.id.timing_btn5;
                                                TextView textView9 = (TextView) view.findViewById(R.id.timing_btn5);
                                                if (textView9 != null) {
                                                    return new DialogTimingBottomNightBinding((LinearLayout) view, textView, textView2, textView3, textView4, imageView, findViewById, textView5, textView6, textView7, textView8, textView9);
                                                }
                                            }
                                        }
                                    }
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
    public static DialogTimingBottomNightBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogTimingBottomNightBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_timing_bottom_night, viewGroup, false);
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
