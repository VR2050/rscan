package com.jbzd.media.movecartoons.p396ui.index.home;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.BloggerOrderBean;
import com.jbzd.media.movecartoons.bean.response.HomeComicsBlockBean;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.bean.response.novel.NovelItemsBean;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.MutablePropertyReference0Impl;
import kotlin.jvm.internal.Reflection;
import kotlin.properties.Delegates;
import kotlin.properties.ReadWriteProperty;
import kotlin.reflect.KProperty;
import kotlin.text.StringsKt__StringNumberConversionsKt;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import kotlin.text.Typography;
import org.jetbrains.annotations.NotNull;
import p005b.p143g.p144a.C1558h;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2852c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000<\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0006\n\u0000\n\u0002\u0010\u000b\n\u0002\b\b\n\u0002\u0010\u0002\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b \u001a\u0081\u0001\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u0001\u001a\u00020\u00002\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\b\b\u0002\u0010\u0007\u001a\u00020\u00062\b\b\u0002\u0010\t\u001a\u00020\b2\b\b\u0002\u0010\n\u001a\u00020\b2\b\b\u0002\u0010\u000b\u001a\u00020\b2\b\b\u0002\u0010\f\u001a\u00020\b2\b\b\u0002\u0010\r\u001a\u00020\b2\b\b\u0002\u0010\u000e\u001a\u00020\b2\b\b\u0002\u0010\u000f\u001a\u00020\b2\b\b\u0002\u0010\u0010\u001a\u00020\bH\u0007¢\u0006\u0004\b\u0012\u0010\u0013\u001am\u0010\u0019\u001a\u00020\u00112\u0006\u0010\u0001\u001a\u00020\u00002\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\b\b\u0002\u0010\r\u001a\u00020\b2\b\b\u0002\u0010\u0014\u001a\u00020\b2\b\b\u0002\u0010\u0015\u001a\u00020\b2\b\b\u0002\u0010\u0016\u001a\u00020\b2\b\b\u0002\u0010\f\u001a\u00020\b2\b\b\u0002\u0010\u0017\u001a\u00020\b2\b\b\u0002\u0010\u0018\u001a\u00020\bH\u0007¢\u0006\u0004\b\u0019\u0010\u001a\u001a-\u0010\u001b\u001a\u00020\u00112\u0006\u0010\u0001\u001a\u00020\u00002\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0018\u001a\u00020\b¢\u0006\u0004\b\u001b\u0010\u001c\u001aw\u0010\u001f\u001a\u00020\u00112\u0006\u0010\u0001\u001a\u00020\u00002\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u001d2\b\b\u0002\u0010\r\u001a\u00020\b2\b\b\u0002\u0010\u0014\u001a\u00020\b2\b\b\u0002\u0010\u0015\u001a\u00020\b2\b\b\u0002\u0010\u0016\u001a\u00020\b2\b\b\u0002\u0010\f\u001a\u00020\b2\b\b\u0002\u0010\u0017\u001a\u00020\b2\b\b\u0002\u0010\u001e\u001a\u00020\b2\b\b\u0002\u0010\u0018\u001a\u00020\bH\u0007¢\u0006\u0004\b\u001f\u0010 \u001a{\u0010#\u001a\u00020\u00112\u0006\u0010\u0001\u001a\u00020\u00002\u0006\u0010\u0003\u001a\u00020\u00022\n\u0010\u0005\u001a\u00060!R\u00020\"2\b\b\u0002\u0010\r\u001a\u00020\b2\b\b\u0002\u0010\u0014\u001a\u00020\b2\b\b\u0002\u0010\u0015\u001a\u00020\b2\b\b\u0002\u0010\u0016\u001a\u00020\b2\b\b\u0002\u0010\f\u001a\u00020\b2\b\b\u0002\u0010\u0017\u001a\u00020\b2\b\b\u0002\u0010\u001e\u001a\u00020\b2\b\b\u0002\u0010\u0018\u001a\u00020\bH\u0007¢\u0006\u0004\b#\u0010$\u001a5\u0010%\u001a\u00020\u00112\u0006\u0010\u0001\u001a\u00020\u00002\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u001d2\u0006\u0010\u0018\u001a\u00020\b2\u0006\u0010\u001e\u001a\u00020\b¢\u0006\u0004\b%\u0010&\u001a9\u0010'\u001a\u00020\u00112\u0006\u0010\u0001\u001a\u00020\u00002\u0006\u0010\u0003\u001a\u00020\u00022\n\u0010\u0005\u001a\u00060!R\u00020\"2\u0006\u0010\u0018\u001a\u00020\b2\u0006\u0010\u001e\u001a\u00020\b¢\u0006\u0004\b'\u0010(\"+\u0010\u0014\u001a\u00020\b2\u0006\u0010)\u001a\u00020\b8B@BX\u0082\u008e\u0002¢\u0006\u0012\n\u0004\b*\u0010+\u001a\u0004\b,\u0010-\"\u0004\b.\u0010/\"+\u0010\u0017\u001a\u00020\b2\u0006\u0010)\u001a\u00020\b8B@BX\u0082\u008e\u0002¢\u0006\u0012\n\u0004\b0\u0010+\u001a\u0004\b1\u0010-\"\u0004\b2\u0010/\"+\u0010\u0016\u001a\u00020\b2\u0006\u0010)\u001a\u00020\b8B@BX\u0082\u008e\u0002¢\u0006\u0012\n\u0004\b3\u0010+\u001a\u0004\b4\u0010-\"\u0004\b5\u0010/\"+\u0010\u001e\u001a\u00020\b2\u0006\u0010)\u001a\u00020\b8B@BX\u0082\u008e\u0002¢\u0006\u0012\n\u0004\b6\u0010+\u001a\u0004\b7\u0010-\"\u0004\b8\u0010/\"+\u0010\r\u001a\u00020\b2\u0006\u0010)\u001a\u00020\b8B@BX\u0082\u008e\u0002¢\u0006\u0012\n\u0004\b9\u0010+\u001a\u0004\b:\u0010-\"\u0004\b;\u0010/\"+\u0010\u0015\u001a\u00020\b2\u0006\u0010)\u001a\u00020\b8B@BX\u0082\u008e\u0002¢\u0006\u0012\n\u0004\b<\u0010+\u001a\u0004\b=\u0010-\"\u0004\b>\u0010/\"+\u0010\f\u001a\u00020\b2\u0006\u0010)\u001a\u00020\b8B@BX\u0082\u008e\u0002¢\u0006\u0012\n\u0004\b?\u0010+\u001a\u0004\b@\u0010-\"\u0004\bA\u0010/¨\u0006B"}, m5311d2 = {"Landroid/content/Context;", "context", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "item", "", "roundDp", "", "showLike", "hideDuration", "hidePlayNumber", "showZhiding", "showVideoName", "showVideoOption", "isModuleImg", "hideItvPrice", "", "showVideoItemMsg", "(Landroid/content/Context;Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;DZZZZZZZZ)V", "showItvPrice", "showPlayNumber", "showDuration", "showThumbs", "isWaterfall", "showVideoItemMsgNew", "(Landroid/content/Context;Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;ZZZZZZZ)V", "showVideo", "(Landroid/content/Context;Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;Z)V", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelItemsBean;", "showNewHotFree", "showNovelItemNew", "(Landroid/content/Context;Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/novel/NovelItemsBean;ZZZZZZZZ)V", "Lcom/jbzd/media/movecartoons/bean/response/HomeComicsBlockBean$ComicsItemBean;", "Lcom/jbzd/media/movecartoons/bean/response/HomeComicsBlockBean;", "showComicsItemMsgNew", "(Landroid/content/Context;Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/HomeComicsBlockBean$ComicsItemBean;ZZZZZZZZ)V", "showNovels", "(Landroid/content/Context;Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/novel/NovelItemsBean;ZZ)V", "showComics", "(Landroid/content/Context;Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/HomeComicsBlockBean$ComicsItemBean;ZZ)V", "<set-?>", "showItvPrice$delegate", "Lkotlin/properties/ReadWriteProperty;", "getShowItvPrice", "()Z", "setShowItvPrice", "(Z)V", "showThumbs$delegate", "getShowThumbs", "setShowThumbs", "showDuration$delegate", "getShowDuration", "setShowDuration", "showNewHotFree$delegate", "getShowNewHotFree", "setShowNewHotFree", "showVideoName$delegate", "getShowVideoName", "setShowVideoName", "showPlayNumber$delegate", "getShowPlayNumber", "setShowPlayNumber", "showZhiding$delegate", "getShowZhiding", "setShowZhiding", "app_release"}, m5312k = 2, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class VideoItemShowKt {
    public static final /* synthetic */ KProperty<Object>[] $$delegatedProperties = {Reflection.mutableProperty0(new MutablePropertyReference0Impl(Reflection.getOrCreateKotlinPackage(VideoItemShowKt.class, "app_release"), "showVideoName", "getShowVideoName()Z")), Reflection.mutableProperty0(new MutablePropertyReference0Impl(Reflection.getOrCreateKotlinPackage(VideoItemShowKt.class, "app_release"), "showItvPrice", "getShowItvPrice()Z")), Reflection.mutableProperty0(new MutablePropertyReference0Impl(Reflection.getOrCreateKotlinPackage(VideoItemShowKt.class, "app_release"), "showPlayNumber", "getShowPlayNumber()Z")), Reflection.mutableProperty0(new MutablePropertyReference0Impl(Reflection.getOrCreateKotlinPackage(VideoItemShowKt.class, "app_release"), "showDuration", "getShowDuration()Z")), Reflection.mutableProperty0(new MutablePropertyReference0Impl(Reflection.getOrCreateKotlinPackage(VideoItemShowKt.class, "app_release"), "showZhiding", "getShowZhiding()Z")), Reflection.mutableProperty0(new MutablePropertyReference0Impl(Reflection.getOrCreateKotlinPackage(VideoItemShowKt.class, "app_release"), "showThumbs", "getShowThumbs()Z")), Reflection.mutableProperty0(new MutablePropertyReference0Impl(Reflection.getOrCreateKotlinPackage(VideoItemShowKt.class, "app_release"), "showNewHotFree", "getShowNewHotFree()Z"))};

    @NotNull
    private static final ReadWriteProperty showDuration$delegate;

    @NotNull
    private static final ReadWriteProperty showItvPrice$delegate;

    @NotNull
    private static final ReadWriteProperty showNewHotFree$delegate;

    @NotNull
    private static final ReadWriteProperty showPlayNumber$delegate;

    @NotNull
    private static final ReadWriteProperty showThumbs$delegate;

    @NotNull
    private static final ReadWriteProperty showVideoName$delegate;

    @NotNull
    private static final ReadWriteProperty showZhiding$delegate;

    static {
        Delegates delegates = Delegates.INSTANCE;
        showVideoName$delegate = delegates.notNull();
        showItvPrice$delegate = delegates.notNull();
        showPlayNumber$delegate = delegates.notNull();
        showDuration$delegate = delegates.notNull();
        showZhiding$delegate = delegates.notNull();
        showThumbs$delegate = delegates.notNull();
        showNewHotFree$delegate = delegates.notNull();
    }

    private static final boolean getShowDuration() {
        return ((Boolean) showDuration$delegate.getValue(null, $$delegatedProperties[3])).booleanValue();
    }

    private static final boolean getShowItvPrice() {
        return ((Boolean) showItvPrice$delegate.getValue(null, $$delegatedProperties[1])).booleanValue();
    }

    private static final boolean getShowNewHotFree() {
        return ((Boolean) showNewHotFree$delegate.getValue(null, $$delegatedProperties[6])).booleanValue();
    }

    private static final boolean getShowPlayNumber() {
        return ((Boolean) showPlayNumber$delegate.getValue(null, $$delegatedProperties[2])).booleanValue();
    }

    private static final boolean getShowThumbs() {
        return ((Boolean) showThumbs$delegate.getValue(null, $$delegatedProperties[5])).booleanValue();
    }

    private static final boolean getShowVideoName() {
        return ((Boolean) showVideoName$delegate.getValue(null, $$delegatedProperties[0])).booleanValue();
    }

    private static final boolean getShowZhiding() {
        return ((Boolean) showZhiding$delegate.getValue(null, $$delegatedProperties[4])).booleanValue();
    }

    private static final void setShowDuration(boolean z) {
        showDuration$delegate.setValue(null, $$delegatedProperties[3], Boolean.valueOf(z));
    }

    private static final void setShowItvPrice(boolean z) {
        showItvPrice$delegate.setValue(null, $$delegatedProperties[1], Boolean.valueOf(z));
    }

    private static final void setShowNewHotFree(boolean z) {
        showNewHotFree$delegate.setValue(null, $$delegatedProperties[6], Boolean.valueOf(z));
    }

    private static final void setShowPlayNumber(boolean z) {
        showPlayNumber$delegate.setValue(null, $$delegatedProperties[2], Boolean.valueOf(z));
    }

    private static final void setShowThumbs(boolean z) {
        showThumbs$delegate.setValue(null, $$delegatedProperties[5], Boolean.valueOf(z));
    }

    private static final void setShowVideoName(boolean z) {
        showVideoName$delegate.setValue(null, $$delegatedProperties[0], Boolean.valueOf(z));
    }

    private static final void setShowZhiding(boolean z) {
        showZhiding$delegate.setValue(null, $$delegatedProperties[4], Boolean.valueOf(z));
    }

    public static final void showComics(@NotNull Context context, @NotNull BaseViewHolder helper, @NotNull HomeComicsBlockBean.ComicsItemBean item, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        if (helper.m3914d(R.id.itv_ad)) {
            helper.m3916f(R.id.itv_ad, true);
        }
        if (helper.m3914d(R.id.itv_clicks)) {
            helper.m3916f(R.id.itv_clicks, !getShowPlayNumber());
            String str = item.name;
            if (str == null) {
                str = "0";
            }
            helper.m3919i(R.id.itv_clicks, str);
            TextView textView = (TextView) helper.m3912b(R.id.itv_clicks);
            textView.setTextSize(13.0f);
            textView.setCompoundDrawables(null, null, null, null);
        }
        if (helper.m3914d(R.id.iv_video)) {
            ImageView imageView = (ImageView) helper.m3912b(R.id.iv_video);
            helper.m3916f(R.id.iv_video, false);
            C2852c c2852c = (C2852c) ComponentCallbacks2C1553c.m738h(context);
            String str2 = item.img;
            if (str2 == null) {
                str2 = "";
            }
            C1558h mo770c = c2852c.mo770c();
            mo770c.mo763X(str2);
            ((C2851b) mo770c).m3292f0().m757R(imageView);
        }
        if (helper.m3914d(R.id.tv_duration)) {
            helper.m3916f(R.id.tv_duration, true);
        }
        if (helper.m3914d(R.id.iv_ico_type)) {
            helper.m3916f(R.id.iv_ico_type, z2);
            ImageView imageView2 = (ImageView) helper.m3912b(R.id.iv_ico_type);
            if (item.ico.equals(BloggerOrderBean.order_new)) {
                imageView2.setVisibility(0);
                ((C2852c) ComponentCallbacks2C1553c.m738h(context)).m3297o(Integer.valueOf(R.drawable.icon_mh_new)).m3295i0().m757R(imageView2);
            } else if (item.ico.equals("hot")) {
                imageView2.setVisibility(0);
                ((C2852c) ComponentCallbacks2C1553c.m738h(context)).m3297o(Integer.valueOf(R.drawable.icon_mh_hot)).m3295i0().m757R(imageView2);
            } else {
                imageView2.setVisibility(8);
            }
        }
        if (helper.m3914d(R.id.ll_name)) {
            if (helper.m3914d(R.id.tv_name)) {
                helper.m3916f(R.id.tv_name, false);
                String str3 = item.sub_title;
                Intrinsics.checkNotNullExpressionValue(str3, "item.sub_title");
                helper.m3919i(R.id.tv_name, StringsKt__StringsKt.trim((CharSequence) str3).toString());
            }
            if (helper.m3914d(R.id.tv_name_categories)) {
                String str4 = item.category;
                Intrinsics.checkNotNullExpressionValue(str4, "item.category");
                helper.m3919i(R.id.tv_name_categories, StringsKt__StringsKt.trim((CharSequence) str4).toString());
                if (item.category.equals("")) {
                    helper.m3911a(R.id.tv_name_categories, true);
                } else {
                    helper.m3911a(R.id.tv_name_categories, false);
                }
            }
        }
    }

    @SuppressLint({"SetTextI18n", "UseCompatLoadingForDrawables"})
    public static final void showComicsItemMsgNew(@NotNull Context context, @NotNull BaseViewHolder helper, @NotNull HomeComicsBlockBean.ComicsItemBean item, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6, boolean z7, boolean z8) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        setShowVideoName(z);
        setShowItvPrice(z2);
        setShowPlayNumber(z3);
        setShowDuration(z4);
        setShowZhiding(z5);
        setShowThumbs(z6);
        setShowNewHotFree(z7);
        if (helper.m3914d(R.id.text_price_type)) {
            helper.m3916f(R.id.text_price_type, true);
        }
        if (helper.m3914d(R.id.iv_videoOption)) {
            helper.m3916f(R.id.iv_videoOption, true);
        }
        if (helper.m3914d(R.id.rl_coverOption)) {
            helper.m3916f(R.id.rl_coverOption, false);
        }
        showComics(context, helper, item, z8, z7);
    }

    @SuppressLint({"SetTextI18n", "UseCompatLoadingForDrawables"})
    public static final void showNovelItemNew(@NotNull Context context, @NotNull BaseViewHolder helper, @NotNull NovelItemsBean item, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6, boolean z7, boolean z8) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        setShowVideoName(z);
        setShowItvPrice(z2);
        setShowPlayNumber(z3);
        setShowDuration(z4);
        setShowZhiding(z5);
        setShowThumbs(z6);
        setShowNewHotFree(z7);
        if (helper.m3914d(R.id.text_price_type)) {
            helper.m3916f(R.id.text_price_type, true);
        }
        if (helper.m3914d(R.id.iv_videoOption)) {
            helper.m3916f(R.id.iv_videoOption, true);
        }
        if (helper.m3914d(R.id.rl_coverOption)) {
            helper.m3916f(R.id.rl_coverOption, false);
        }
        showNovels(context, helper, item, z8, z7);
    }

    public static final void showNovels(@NotNull Context context, @NotNull BaseViewHolder helper, @NotNull NovelItemsBean item, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        if (helper.m3914d(R.id.itv_ad)) {
            helper.m3916f(R.id.itv_ad, true);
        }
        if (helper.m3914d(R.id.itv_clicks)) {
            helper.m3916f(R.id.itv_clicks, !getShowPlayNumber());
            String name = item.getName();
            if (name == null) {
                name = "0";
            }
            helper.m3919i(R.id.itv_clicks, name);
            TextView textView = (TextView) helper.m3912b(R.id.itv_clicks);
            textView.setTextSize(13.0f);
            textView.setCompoundDrawables(null, null, null, null);
        }
        if (helper.m3914d(R.id.iv_novel_audio)) {
            if (item.getIco().equals("audio") && item.getType().equals("novel")) {
                helper.m3916f(R.id.iv_novel_audio, false);
            } else {
                helper.m3916f(R.id.iv_novel_audio, true);
            }
        }
        if (helper.m3914d(R.id.iv_video)) {
            ImageView imageView = (ImageView) helper.m3912b(R.id.iv_video);
            helper.m3916f(R.id.iv_video, false);
            C2852c c2852c = (C2852c) ComponentCallbacks2C1553c.m738h(context);
            String img = item.getImg();
            if (img == null) {
                img = "";
            }
            C1558h mo770c = c2852c.mo770c();
            mo770c.mo763X(img);
            ((C2851b) mo770c).m3292f0().m757R(imageView);
        }
        if (helper.m3914d(R.id.tv_duration)) {
            helper.m3916f(R.id.tv_duration, true);
        }
        if (helper.m3914d(R.id.iv_ico_type)) {
            helper.m3916f(R.id.iv_ico_type, z2);
            ImageView imageView2 = (ImageView) helper.m3912b(R.id.iv_ico_type);
            if (item.getIco().equals(BloggerOrderBean.order_new)) {
                imageView2.setVisibility(0);
                ((C2852c) ComponentCallbacks2C1553c.m738h(context)).m3297o(Integer.valueOf(R.drawable.icon_mh_new)).m3295i0().m757R(imageView2);
            } else if (item.getIco().equals("hot")) {
                imageView2.setVisibility(0);
                ((C2852c) ComponentCallbacks2C1553c.m738h(context)).m3297o(Integer.valueOf(R.drawable.icon_mh_hot)).m3295i0().m757R(imageView2);
            } else {
                imageView2.setVisibility(8);
            }
        }
        if (helper.m3914d(R.id.ll_name)) {
            helper.m3916f(R.id.ll_name, !getShowVideoName());
            if (helper.m3914d(R.id.tv_name)) {
                helper.m3919i(R.id.tv_name, item.getName());
                ((TextView) helper.m3912b(R.id.tv_video_click)).setText(item.getCategory_name() + Typography.middleDot + ((Object) item.getSub_title()));
            }
            if (helper.m3914d(R.id.tv_name_categories)) {
                if (item.getType().equals("novel")) {
                    String category_name = item.getCategory_name();
                    Intrinsics.checkNotNullExpressionValue(category_name, "item.category_name");
                    helper.m3919i(R.id.tv_name_categories, StringsKt__StringsKt.trim((CharSequence) category_name).toString());
                } else {
                    String category = item.getCategory();
                    Intrinsics.checkNotNullExpressionValue(category, "item.category");
                    helper.m3919i(R.id.tv_name_categories, StringsKt__StringsKt.trim((CharSequence) category).toString());
                }
                if (item.getCategory().equals("")) {
                    helper.m3911a(R.id.tv_name_categories, true);
                } else {
                    helper.m3911a(R.id.tv_name_categories, false);
                }
            }
        }
    }

    public static final void showVideo(@NotNull Context context, @NotNull BaseViewHolder helper, @NotNull VideoItemBean item, boolean z) {
        String str;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        if (item.getIsAd()) {
            if (helper.m3914d(R.id.ll_ad_new)) {
                helper.m3916f(R.id.ll_ad_new, false);
            }
            if (helper.m3914d(R.id.tv_duration)) {
                helper.m3916f(R.id.tv_duration, true);
            }
        } else {
            if (helper.m3914d(R.id.ll_ad_new)) {
                helper.m3916f(R.id.ll_ad_new, true);
            }
            if (helper.m3914d(R.id.tv_duration)) {
                helper.m3916f(R.id.tv_duration, false);
            }
        }
        if (helper.m3914d(R.id.itv_ad)) {
            helper.m3916f(R.id.itv_ad, true);
        }
        if (helper.m3914d(R.id.itv_clicks)) {
            helper.m3916f(R.id.itv_clicks, !getShowPlayNumber());
            CharSequence charSequence = item.click;
            if (charSequence == null) {
                charSequence = "0";
            }
            helper.m3919i(R.id.itv_clicks, charSequence);
        }
        str = "";
        if (helper.m3914d(R.id.iv_video)) {
            ImageView imageView = (ImageView) helper.m3912b(R.id.iv_video);
            helper.m3916f(R.id.iv_video, false);
            C2852c c2852c = (C2852c) ComponentCallbacks2C1553c.m738h(context);
            String str2 = item.img_x;
            if (str2 == null) {
                str2 = "";
            }
            C1558h mo770c = c2852c.mo770c();
            mo770c.mo763X(str2);
            ((C2851b) mo770c).m3295i0().m757R(imageView);
        }
        if (helper.m3914d(R.id.tv_duration)) {
            helper.m3916f(R.id.tv_duration, !getShowDuration());
            String str3 = item.duration;
            Intrinsics.checkNotNullExpressionValue(str3, "item.duration");
            if (StringsKt__StringsJVMKt.startsWith$default(str3, "00:", false, 2, null)) {
                String str4 = item.duration;
                Intrinsics.checkNotNullExpressionValue(str4, "item.duration");
                helper.m3919i(R.id.tv_duration, StringsKt__StringsJVMKt.replace$default(str4, "00:", "", false, 4, (Object) null));
            } else {
                CharSequence charSequence2 = item.duration;
                if (charSequence2 == null) {
                    charSequence2 = "";
                }
                helper.m3919i(R.id.tv_duration, charSequence2);
            }
        }
        if (helper.m3914d(R.id.itv_zhiding)) {
            helper.m3916f(R.id.itv_zhiding, !getShowZhiding());
        }
        if (helper.m3914d(R.id.ll_name)) {
            helper.m3916f(R.id.ll_name, false);
            if (helper.m3914d(R.id.tv_name)) {
                helper.m3916f(R.id.tv_name, false);
                String str5 = item.name;
                Intrinsics.checkNotNullExpressionValue(str5, "item.name");
                helper.m3919i(R.id.tv_name, StringsKt__StringsKt.trim((CharSequence) str5).toString());
            }
        }
        if (helper.m3914d(R.id.tv_video_click)) {
            helper.m3916f(R.id.tv_video_click, false);
            helper.m3919i(R.id.tv_video_click, Intrinsics.stringPlus("人气·", item.click));
            if (item.getIsAd()) {
                helper.m3916f(R.id.tv_video_click, true);
            } else {
                helper.m3916f(R.id.tv_video_click, false);
            }
        }
        if (helper.m3914d(R.id.tv_thumbs)) {
            helper.m3916f(R.id.tv_thumbs, !getShowThumbs());
            if (Intrinsics.areEqual(item.canvas, "short")) {
                TextView textView = (TextView) helper.m3912b(R.id.tv_thumbs);
                textView.setCompoundDrawablesWithIntrinsicBounds(context.getDrawable(R.drawable.icon_collect), (Drawable) null, (Drawable) null, (Drawable) null);
                textView.setCompoundDrawablePadding(4);
            }
        }
        TextView textView2 = (TextView) helper.m3913c(R.id.itv_icon_money);
        View m3913c = helper.m3913c(R.id.tv_video_type);
        View m3913c2 = helper.m3913c(R.id.iv_ico_type);
        ((LinearLayout) helper.m3912b(R.id.ll_money_vip)).setVisibility(0);
        if (item.getIsVipVideo()) {
            if (textView2 != null) {
                textView2.setVisibility(8);
            }
            if (m3913c != null) {
                m3913c.setVisibility(0);
            }
            if (m3913c2 != null) {
                m3913c2.setVisibility(8);
            }
        } else {
            String str6 = item.money;
            Intrinsics.checkNotNullExpressionValue(str6, "item.money");
            Integer intOrNull = StringsKt__StringNumberConversionsKt.toIntOrNull(str6);
            if (intOrNull != null) {
                if (intOrNull.intValue() > 0) {
                    if (m3913c != null) {
                        m3913c.setVisibility(8);
                    }
                    if (textView2 != null) {
                        textView2.setVisibility(0);
                    }
                    if (textView2 != null) {
                        textView2.setText(item.money);
                    }
                    if (m3913c2 != null) {
                        m3913c2.setVisibility(8);
                    }
                } else {
                    if (m3913c != null) {
                        m3913c.setVisibility(8);
                    }
                    if (textView2 != null) {
                        textView2.setVisibility(8);
                    }
                    if (item.getIsAd()) {
                        if (m3913c2 != null) {
                            m3913c2.setVisibility(8);
                        }
                    } else if (m3913c2 != null) {
                        m3913c2.setVisibility(0);
                    }
                }
            }
        }
        if (z) {
            String str7 = item.img_type;
            Intrinsics.checkNotNullExpressionValue(str7, "item.img_type");
            if (str7.length() > 0) {
                if (item.img_type.equals("short")) {
                    if (helper.m3914d(R.id.iv_video) && helper.m3914d(R.id.srl_coverParent_img)) {
                        helper.m3916f(R.id.srl_coverParent_img, true);
                    }
                    if (helper.m3914d(R.id.iv_video_vertical)) {
                        if (helper.m3914d(R.id.srl_coverParent_vertical)) {
                            helper.m3916f(R.id.srl_coverParent_vertical, false);
                        }
                        ImageView imageView2 = (ImageView) helper.m3912b(R.id.iv_video_vertical);
                        C2852c c2852c2 = (C2852c) ComponentCallbacks2C1553c.m738h(context);
                        String str8 = item.img_x;
                        str = str8 != null ? str8 : "";
                        C1558h mo770c2 = c2852c2.mo770c();
                        mo770c2.mo763X(str);
                        ((C2851b) mo770c2).m3292f0().m757R(imageView2);
                    }
                } else {
                    if (helper.m3914d(R.id.iv_video)) {
                        if (helper.m3914d(R.id.srl_coverParent_img)) {
                            helper.m3916f(R.id.srl_coverParent_img, false);
                        }
                        ImageView imageView3 = (ImageView) helper.m3912b(R.id.iv_video);
                        C2852c c2852c3 = (C2852c) ComponentCallbacks2C1553c.m738h(context);
                        String str9 = item.img_x;
                        str = str9 != null ? str9 : "";
                        C1558h mo770c3 = c2852c3.mo770c();
                        mo770c3.mo763X(str);
                        ((C2851b) mo770c3).m3295i0().m757R(imageView3);
                    }
                    if (helper.m3914d(R.id.iv_video_vertical) && helper.m3914d(R.id.srl_coverParent_vertical)) {
                        helper.m3916f(R.id.srl_coverParent_vertical, true);
                    }
                }
            }
            if (helper.m3914d(R.id.itv_price)) {
                helper.m3916f(R.id.itv_price, false);
            }
            if (helper.m3914d(R.id.itv_type)) {
                helper.m3916f(R.id.itv_type, true);
            }
        } else {
            if (helper.m3914d(R.id.iv_video)) {
                if (helper.m3914d(R.id.srl_coverParent_img)) {
                    helper.m3916f(R.id.srl_coverParent_img, false);
                }
                ImageView imageView4 = (ImageView) helper.m3912b(R.id.iv_video);
                C2852c c2852c4 = (C2852c) ComponentCallbacks2C1553c.m738h(context);
                String str10 = item.img_x;
                if (str10 == null) {
                    str10 = "";
                }
                C1558h mo770c4 = c2852c4.mo770c();
                mo770c4.mo763X(str10);
                ((C2851b) mo770c4).m3292f0().m757R(imageView4);
            }
            if (helper.m3914d(R.id.iv_video_vertical) && helper.m3914d(R.id.srl_coverParent_vertical)) {
                helper.m3916f(R.id.srl_coverParent_vertical, true);
            }
            if (helper.m3914d(R.id.ll_bottom_cover)) {
                helper.m3916f(R.id.ll_bottom_cover, false);
            }
            if (helper.m3914d(R.id.itv_clicks)) {
                helper.m3916f(R.id.itv_clicks, false);
                helper.m3919i(R.id.itv_clicks, item.click);
            }
            try {
                helper.m3916f(R.id.tv_duration, false);
                String str11 = item.duration;
                Intrinsics.checkNotNullExpressionValue(str11, "item.duration");
                if (StringsKt__StringsJVMKt.startsWith$default(str11, "00:", false, 2, null)) {
                    String str12 = item.duration;
                    Intrinsics.checkNotNullExpressionValue(str12, "item.duration");
                    helper.m3919i(R.id.tv_duration, StringsKt__StringsJVMKt.replace$default(str12, "00:", "", false, 4, (Object) null));
                } else {
                    String str13 = item.duration;
                    if (str13 != null) {
                        str = str13;
                    }
                    helper.m3919i(R.id.tv_duration, str);
                }
            } catch (Exception unused) {
            }
        }
        if (item.getIsAd()) {
            if (helper.m3914d(R.id.tv_duration)) {
                helper.m3916f(R.id.tv_duration, true);
            }
        } else if (helper.m3914d(R.id.tv_duration)) {
            helper.m3916f(R.id.tv_duration, false);
        }
    }

    /*  JADX ERROR: JadxRuntimeException in pass: RegionMakerVisitor
        jadx.core.utils.exceptions.JadxRuntimeException: Can't find top splitter block for handler:B:30:0x01f7
        	at jadx.core.utils.BlockUtils.getTopSplitterForHandler(BlockUtils.java:1179)
        	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.collectHandlerRegions(ExcHandlersRegionMaker.java:53)
        	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.process(ExcHandlersRegionMaker.java:38)
        	at jadx.core.dex.visitors.regions.RegionMakerVisitor.visit(RegionMakerVisitor.java:27)
        */
    @kotlin.Deprecated(message = "請使用showVideoItemMsgNew函式")
    @androidx.annotation.RequiresApi(23)
    public static final void showVideoItemMsg(@org.jetbrains.annotations.NotNull android.content.Context r18, @org.jetbrains.annotations.NotNull com.chad.library.adapter.base.viewholder.BaseViewHolder r19, @org.jetbrains.annotations.NotNull com.jbzd.media.movecartoons.bean.response.VideoItemBean r20, double r21, boolean r23, boolean r24, boolean r25, boolean r26, boolean r27, boolean r28, boolean r29, boolean r30) {
        /*
            Method dump skipped, instructions count: 753
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.index.home.VideoItemShowKt.showVideoItemMsg(android.content.Context, com.chad.library.adapter.base.viewholder.BaseViewHolder, com.jbzd.media.movecartoons.bean.response.VideoItemBean, double, boolean, boolean, boolean, boolean, boolean, boolean, boolean, boolean):void");
    }

    @SuppressLint({"SetTextI18n", "UseCompatLoadingForDrawables"})
    public static final void showVideoItemMsgNew(@NotNull Context context, @NotNull BaseViewHolder helper, @NotNull VideoItemBean item, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, boolean z6, boolean z7) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        setShowVideoName(z);
        setShowItvPrice(z2);
        setShowPlayNumber(z3);
        setShowDuration(z4);
        setShowZhiding(z5);
        setShowThumbs(z6);
        if (helper.m3914d(R.id.text_price_type)) {
            helper.m3916f(R.id.text_price_type, true);
        }
        if (helper.m3914d(R.id.iv_videoOption)) {
            helper.m3916f(R.id.iv_videoOption, true);
        }
        if (helper.m3914d(R.id.rl_coverOption)) {
            helper.m3916f(R.id.rl_coverOption, false);
        }
        showVideo(context, helper, item, z7);
    }
}
