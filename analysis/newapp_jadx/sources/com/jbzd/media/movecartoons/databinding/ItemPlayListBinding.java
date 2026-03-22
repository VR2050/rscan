package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.SeekBar;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.FollowTextView;
import com.jbzd.media.movecartoons.view.ProgressButton;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.jbzd.media.movecartoons.view.video.ListPlayerView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemPlayListBinding implements ViewBinding {

    @NonNull
    public final CircleImageView civHead;

    @NonNull
    public final TextView etvName;

    @NonNull
    public final FrameLayout flVideo;

    @NonNull
    public final FrameLayout frameLayout;

    @NonNull
    public final ImageTextView itvDownload;

    @NonNull
    public final ImageTextView itvFavorite;

    @NonNull
    public final ImageTextView itvLove;

    @NonNull
    public final ImageTextView itvShare;

    @NonNull
    public final ImageView ivAd;

    @NonNull
    public final ImageView ivClearScreen;

    @NonNull
    public final FollowTextView ivUserFollow;

    @NonNull
    public final ImageView ivVideoFullscreen;

    @NonNull
    public final LinearLayout llBottomContent;

    @NonNull
    public final LinearLayout llBottomItem;

    @NonNull
    public final LinearLayout llBottomTool;

    @NonNull
    public final RelativeLayout llMineInfo;

    @NonNull
    public final LinearLayout llPlayer;

    @NonNull
    public final LinearLayout llProgressBar;

    @NonNull
    public final LinearLayout llVideoMsg;

    @NonNull
    public final ProgressButton pbGoKnown;

    @NonNull
    public final SeekBar progressForeground;

    @NonNull
    public final RelativeLayout rlAd;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final RecyclerView rvTag;

    @NonNull
    public final TextView tvAdName;

    @NonNull
    public final TextView tvBuy;

    @NonNull
    public final TextView tvCurDuration;

    @NonNull
    public final ImageTextView tvShoworhiden;

    @NonNull
    public final ImageTextView tvSpinnerShort;

    @NonNull
    public final TextView tvTotalDuration;

    @NonNull
    public final TextView tvUsernameUpper;

    @NonNull
    public final ListPlayerView videoPlayer;

    private ItemPlayListBinding(@NonNull FrameLayout frameLayout, @NonNull CircleImageView circleImageView, @NonNull TextView textView, @NonNull FrameLayout frameLayout2, @NonNull FrameLayout frameLayout3, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull ImageTextView imageTextView3, @NonNull ImageTextView imageTextView4, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull FollowTextView followTextView, @NonNull ImageView imageView3, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull RelativeLayout relativeLayout, @NonNull LinearLayout linearLayout4, @NonNull LinearLayout linearLayout5, @NonNull LinearLayout linearLayout6, @NonNull ProgressButton progressButton, @NonNull SeekBar seekBar, @NonNull RelativeLayout relativeLayout2, @NonNull RecyclerView recyclerView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull ImageTextView imageTextView5, @NonNull ImageTextView imageTextView6, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull ListPlayerView listPlayerView) {
        this.rootView = frameLayout;
        this.civHead = circleImageView;
        this.etvName = textView;
        this.flVideo = frameLayout2;
        this.frameLayout = frameLayout3;
        this.itvDownload = imageTextView;
        this.itvFavorite = imageTextView2;
        this.itvLove = imageTextView3;
        this.itvShare = imageTextView4;
        this.ivAd = imageView;
        this.ivClearScreen = imageView2;
        this.ivUserFollow = followTextView;
        this.ivVideoFullscreen = imageView3;
        this.llBottomContent = linearLayout;
        this.llBottomItem = linearLayout2;
        this.llBottomTool = linearLayout3;
        this.llMineInfo = relativeLayout;
        this.llPlayer = linearLayout4;
        this.llProgressBar = linearLayout5;
        this.llVideoMsg = linearLayout6;
        this.pbGoKnown = progressButton;
        this.progressForeground = seekBar;
        this.rlAd = relativeLayout2;
        this.rvTag = recyclerView;
        this.tvAdName = textView2;
        this.tvBuy = textView3;
        this.tvCurDuration = textView4;
        this.tvShoworhiden = imageTextView5;
        this.tvSpinnerShort = imageTextView6;
        this.tvTotalDuration = textView5;
        this.tvUsernameUpper = textView6;
        this.videoPlayer = listPlayerView;
    }

    @NonNull
    public static ItemPlayListBinding bind(@NonNull View view) {
        int i2 = R.id.civ_head;
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.civ_head);
        if (circleImageView != null) {
            i2 = R.id.etv_name;
            TextView textView = (TextView) view.findViewById(R.id.etv_name);
            if (textView != null) {
                i2 = R.id.flVideo;
                FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.flVideo);
                if (frameLayout != null) {
                    FrameLayout frameLayout2 = (FrameLayout) view;
                    i2 = R.id.itv_download;
                    ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_download);
                    if (imageTextView != null) {
                        i2 = R.id.itv_favorite;
                        ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.itv_favorite);
                        if (imageTextView2 != null) {
                            i2 = R.id.itv_love;
                            ImageTextView imageTextView3 = (ImageTextView) view.findViewById(R.id.itv_love);
                            if (imageTextView3 != null) {
                                i2 = R.id.itv_share;
                                ImageTextView imageTextView4 = (ImageTextView) view.findViewById(R.id.itv_share);
                                if (imageTextView4 != null) {
                                    i2 = R.id.iv_ad;
                                    ImageView imageView = (ImageView) view.findViewById(R.id.iv_ad);
                                    if (imageView != null) {
                                        i2 = R.id.iv_clearScreen;
                                        ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_clearScreen);
                                        if (imageView2 != null) {
                                            i2 = R.id.iv_userFollow;
                                            FollowTextView followTextView = (FollowTextView) view.findViewById(R.id.iv_userFollow);
                                            if (followTextView != null) {
                                                i2 = R.id.iv_video_fullscreen;
                                                ImageView imageView3 = (ImageView) view.findViewById(R.id.iv_video_fullscreen);
                                                if (imageView3 != null) {
                                                    i2 = R.id.ll_bottom_content;
                                                    LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_bottom_content);
                                                    if (linearLayout != null) {
                                                        i2 = R.id.ll_bottom_item;
                                                        LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_bottom_item);
                                                        if (linearLayout2 != null) {
                                                            i2 = R.id.ll_bottom_tool;
                                                            LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_bottom_tool);
                                                            if (linearLayout3 != null) {
                                                                i2 = R.id.ll_mine_info;
                                                                RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.ll_mine_info);
                                                                if (relativeLayout != null) {
                                                                    i2 = R.id.ll_player;
                                                                    LinearLayout linearLayout4 = (LinearLayout) view.findViewById(R.id.ll_player);
                                                                    if (linearLayout4 != null) {
                                                                        i2 = R.id.ll_progressBar;
                                                                        LinearLayout linearLayout5 = (LinearLayout) view.findViewById(R.id.ll_progressBar);
                                                                        if (linearLayout5 != null) {
                                                                            i2 = R.id.ll_videoMsg;
                                                                            LinearLayout linearLayout6 = (LinearLayout) view.findViewById(R.id.ll_videoMsg);
                                                                            if (linearLayout6 != null) {
                                                                                i2 = R.id.pb_goKnown;
                                                                                ProgressButton progressButton = (ProgressButton) view.findViewById(R.id.pb_goKnown);
                                                                                if (progressButton != null) {
                                                                                    i2 = R.id.progress_foreground;
                                                                                    SeekBar seekBar = (SeekBar) view.findViewById(R.id.progress_foreground);
                                                                                    if (seekBar != null) {
                                                                                        i2 = R.id.rl_ad;
                                                                                        RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.rl_ad);
                                                                                        if (relativeLayout2 != null) {
                                                                                            i2 = R.id.rv_tag;
                                                                                            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_tag);
                                                                                            if (recyclerView != null) {
                                                                                                i2 = R.id.tv_adName;
                                                                                                TextView textView2 = (TextView) view.findViewById(R.id.tv_adName);
                                                                                                if (textView2 != null) {
                                                                                                    i2 = R.id.tv_buy;
                                                                                                    TextView textView3 = (TextView) view.findViewById(R.id.tv_buy);
                                                                                                    if (textView3 != null) {
                                                                                                        i2 = R.id.tv_curDuration;
                                                                                                        TextView textView4 = (TextView) view.findViewById(R.id.tv_curDuration);
                                                                                                        if (textView4 != null) {
                                                                                                            i2 = R.id.tv_showorhiden;
                                                                                                            ImageTextView imageTextView5 = (ImageTextView) view.findViewById(R.id.tv_showorhiden);
                                                                                                            if (imageTextView5 != null) {
                                                                                                                i2 = R.id.tv_spinner_short;
                                                                                                                ImageTextView imageTextView6 = (ImageTextView) view.findViewById(R.id.tv_spinner_short);
                                                                                                                if (imageTextView6 != null) {
                                                                                                                    i2 = R.id.tv_totalDuration;
                                                                                                                    TextView textView5 = (TextView) view.findViewById(R.id.tv_totalDuration);
                                                                                                                    if (textView5 != null) {
                                                                                                                        i2 = R.id.tv_username_upper;
                                                                                                                        TextView textView6 = (TextView) view.findViewById(R.id.tv_username_upper);
                                                                                                                        if (textView6 != null) {
                                                                                                                            i2 = R.id.video_player;
                                                                                                                            ListPlayerView listPlayerView = (ListPlayerView) view.findViewById(R.id.video_player);
                                                                                                                            if (listPlayerView != null) {
                                                                                                                                return new ItemPlayListBinding(frameLayout2, circleImageView, textView, frameLayout, frameLayout2, imageTextView, imageTextView2, imageTextView3, imageTextView4, imageView, imageView2, followTextView, imageView3, linearLayout, linearLayout2, linearLayout3, relativeLayout, linearLayout4, linearLayout5, linearLayout6, progressButton, seekBar, relativeLayout2, recyclerView, textView2, textView3, textView4, imageTextView5, imageTextView6, textView5, textView6, listPlayerView);
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
    public static ItemPlayListBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemPlayListBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_play_list, viewGroup, false);
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
