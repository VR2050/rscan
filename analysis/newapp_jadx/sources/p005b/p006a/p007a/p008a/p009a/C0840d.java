package p005b.p006a.p007a.p008a.p009a;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.text.TextUtils;
import com.alibaba.fastjson.asm.Label;
import com.jbzd.media.movecartoons.bean.event.EventChangeTab;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.bean.response.home.NewAd;
import com.jbzd.media.movecartoons.p396ui.appstore.AppStoreActivity;
import com.jbzd.media.movecartoons.p396ui.chat.ChatDetailActivity;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsDetailActivity;
import com.jbzd.media.movecartoons.p396ui.index.IndexActivity;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListActivity;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity;
import com.jbzd.media.movecartoons.p396ui.novel.NovelDetailActivity;
import com.jbzd.media.movecartoons.p396ui.post.topic.PostAiChangeFaceActivity;
import com.jbzd.media.movecartoons.p396ui.post.topic.PostAiClearClosethActivity;
import com.jbzd.media.movecartoons.p396ui.post.topic.PostDetailActivity;
import com.jbzd.media.movecartoons.p396ui.share.InviteActivity;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity;
import com.jbzd.media.movecartoons.p396ui.wallet.RechargeActivity;
import com.jbzd.media.movecartoons.p396ui.web.WebActivity;
import java.util.HashMap;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p476m.p496b.p497a.C4909c;

/* renamed from: b.a.a.a.a.d */
/* loaded from: classes2.dex */
public final class C0840d {

    /* renamed from: a */
    @NotNull
    public static final a f235a = new a(null);

    /* renamed from: b.a.a.a.a.d$a */
    public static final class a {
        public a(DefaultConstructorMarker defaultConstructorMarker) {
        }

        /* renamed from: d */
        public static void m174d(a aVar, Context context, String str, String str2, String str3, int i2) {
            String type = (i2 & 8) != 0 ? "" : null;
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(type, "type");
            if (str == null) {
                return;
            }
            Intrinsics.stringPlus("链接url===", str);
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "share://", 0, false, 6, (Object) null) > -1) {
                InviteActivity.INSTANCE.start(context);
                return;
            }
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "moviedetail://", 0, false, 6, (Object) null) > -1) {
                String substring = str.substring(StringsKt__StringsKt.indexOf$default((CharSequence) str, "moviedetail://", 0, false, 6, (Object) null) + 14, str.length());
                Intrinsics.checkNotNullExpressionValue(substring, "this as java.lang.String…ing(startIndex, endIndex)");
                MovieDetailsActivity.INSTANCE.start(context, substring);
                return;
            }
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "postdetail://", 0, false, 6, (Object) null) > -1) {
                String substring2 = str.substring(StringsKt__StringsKt.indexOf$default((CharSequence) str, "postdetail://", 0, false, 6, (Object) null) + 13, str.length());
                Intrinsics.checkNotNullExpressionValue(substring2, "this as java.lang.String…ing(startIndex, endIndex)");
                PostDetailActivity.INSTANCE.start(context, substring2);
                return;
            }
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "comicdetail://", 0, false, 6, (Object) null) > -1) {
                String substring3 = str.substring(StringsKt__StringsKt.indexOf$default((CharSequence) str, "comicdetail://", 0, false, 6, (Object) null) + 14, str.length());
                Intrinsics.checkNotNullExpressionValue(substring3, "this as java.lang.String…ing(startIndex, endIndex)");
                ComicsDetailActivity.INSTANCE.start(context, substring3);
                return;
            }
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "noveldetail://", 0, false, 6, (Object) null) > -1) {
                String substring4 = str.substring(StringsKt__StringsKt.indexOf$default((CharSequence) str, "noveldetail://", 0, false, 6, (Object) null) + 14, str.length());
                Intrinsics.checkNotNullExpressionValue(substring4, "this as java.lang.String…ing(startIndex, endIndex)");
                NovelDetailActivity.INSTANCE.start(context, substring4);
                return;
            }
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "aity://", 0, false, 6, (Object) null) > -1) {
                PostAiClearClosethActivity.INSTANCE.start(context);
                return;
            }
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "aihl://", 0, false, 6, (Object) null) > -1) {
                PostAiChangeFaceActivity.INSTANCE.startAIChangeFace(context);
                return;
            }
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "buyvip://", 0, false, 6, (Object) null) > -1) {
                BuyActivity.INSTANCE.start(context);
                return;
            }
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "recharge://", 0, false, 6, (Object) null) > -1) {
                RechargeActivity.INSTANCE.start(context);
                return;
            }
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "appstore://", 0, false, 6, (Object) null) > -1) {
                AppStoreActivity.INSTANCE.start(context);
                return;
            }
            if (StringsKt__StringsJVMKt.startsWith$default(str, "http://", false, 2, null) || StringsKt__StringsJVMKt.startsWith$default(str, "https://", false, 2, null)) {
                if (!TextUtils.isEmpty(str)) {
                    Intent intent = new Intent("android.intent.action.VIEW", Uri.parse(str));
                    intent.addFlags(Label.FORWARD_REFERENCE_TYPE_SHORT);
                    context.startActivity(intent);
                    return;
                }
                return;
            }
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "inner://", 0, false, 6, (Object) null) > -1) {
                WebActivity.INSTANCE.start(context, StringsKt__StringsJVMKt.replace$default(str, "inner://", "", false, 4, (Object) null));
                return;
            }
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "shortMovie://", 0, false, 6, (Object) null) > -1) {
                String replace$default = StringsKt__StringsJVMKt.replace$default(str, "shortMovie://", "", false, 4, (Object) null);
                HashMap hashMap = new HashMap();
                if (!(replace$default == null || replace$default.length() == 0)) {
                    try {
                        JSONObject jSONObject = new JSONObject(replace$default);
                        Iterator<String> keys = jSONObject.keys();
                        while (keys.hasNext()) {
                            String key = keys.next();
                            String value = jSONObject.getString(key);
                            Intrinsics.checkNotNullExpressionValue(key, "key");
                            Intrinsics.checkNotNullExpressionValue(value, "value");
                            hashMap.put(key, value);
                        }
                    } catch (Exception e2) {
                        e2.printStackTrace();
                    }
                }
                if (Intrinsics.areEqual(hashMap.get("canvas"), "image")) {
                    PlayListActivity.INSTANCE.start(context, (r13 & 2) != 0 ? null : null, (r13 & 4) != 0 ? null : hashMap, (r13 & 8) != 0 ? null : "photoAlbum/list", (r13 & 16) != 0 ? false : false);
                    return;
                } else {
                    PlayListActivity.INSTANCE.start(context, (r13 & 2) != 0 ? null : null, (r13 & 4) != 0 ? null : hashMap, (r13 & 8) != 0 ? null : null, (r13 & 16) != 0 ? false : false);
                    return;
                }
            }
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "service://", 0, false, 6, (Object) null) > -1) {
                ChatDetailActivity.Companion.start$default(ChatDetailActivity.INSTANCE, context, null, null, null, null, 30, null);
                return;
            }
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "tag://", 0, false, 6, (Object) null) > -1) {
                StringsKt__StringsJVMKt.replace$default(str, "tag://", "", false, 4, (Object) null);
                return;
            }
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "videoList://", 0, false, 6, (Object) null) > -1) {
                String replace$default2 = StringsKt__StringsJVMKt.replace$default(str, "videoList://", "", false, 4, (Object) null);
                HashMap hashMap2 = new HashMap();
                if (!(replace$default2 == null || replace$default2.length() == 0)) {
                    try {
                        JSONObject jSONObject2 = new JSONObject(replace$default2);
                        Iterator<String> keys2 = jSONObject2.keys();
                        while (keys2.hasNext()) {
                            String key2 = keys2.next();
                            String value2 = jSONObject2.getString(key2);
                            Intrinsics.checkNotNullExpressionValue(key2, "key");
                            Intrinsics.checkNotNullExpressionValue(value2, "value");
                            hashMap2.put(key2, value2);
                        }
                    } catch (Exception e3) {
                        e3.printStackTrace();
                    }
                }
                String str4 = (String) hashMap2.get("page_title");
                hashMap2.put("type", type);
                if (str4 == null) {
                    str4 = "视频列表";
                }
                VideoListActivity.Companion.start$default(VideoListActivity.INSTANCE, context, str4, hashMap2, false, 8, null);
                return;
            }
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "homeTab://", 0, false, 6, (Object) null) > -1) {
                String replace$default3 = StringsKt__StringsJVMKt.replace$default(str, "homeTab://", "", false, 4, (Object) null);
                if (context instanceof IndexActivity) {
                    C4909c.m5569b().m5574g(new EventChangeTab(replace$default3, 0));
                    return;
                } else {
                    IndexActivity.Companion.start$default(IndexActivity.INSTANCE, context, new EventChangeTab(replace$default3, 0), false, 4, null);
                    return;
                }
            }
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "tab2Tab://", 0, false, 6, (Object) null) > -1) {
                String replace$default4 = StringsKt__StringsJVMKt.replace$default(str, "tab2Tab://", "", false, 4, (Object) null);
                if (context instanceof IndexActivity) {
                    C4909c.m5569b().m5574g(new EventChangeTab(replace$default4, 1));
                    return;
                } else {
                    IndexActivity.Companion.start$default(IndexActivity.INSTANCE, context, new EventChangeTab(replace$default4, 1), false, 4, null);
                    return;
                }
            }
            if (StringsKt__StringsKt.indexOf$default((CharSequence) str, "tab3Tab://", 0, false, 6, (Object) null) > -1) {
                String replace$default5 = StringsKt__StringsJVMKt.replace$default(str, "tab3Tab://", "", false, 4, (Object) null);
                if (context instanceof IndexActivity) {
                    C4909c.m5569b().m5574g(new EventChangeTab(replace$default5, 2));
                } else {
                    IndexActivity.Companion.start$default(IndexActivity.INSTANCE, context, new EventChangeTab(replace$default5, 2), false, 4, null);
                }
            }
        }

        /* renamed from: a */
        public final void m175a(@NotNull Context context, @NotNull String alink) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(alink, "alink");
            m174d(this, context, alink, null, null, 12);
        }

        /* renamed from: b */
        public final void m176b(@NotNull Context context, @NotNull AdBean bean) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(bean, "bean");
            String id = bean.f10014id;
            Intrinsics.checkNotNullExpressionValue(id, "bean.id");
            String name = bean.name;
            Intrinsics.checkNotNullExpressionValue(name, "bean.name");
            Intrinsics.checkNotNullParameter("ad", "type");
            Intrinsics.checkNotNullParameter(id, "id");
            Intrinsics.checkNotNullParameter(name, "name");
            C0917a c0917a = C0917a.f372a;
            HashMap m596R = C1499a.m596R("object_type", "ad", "object_id", id);
            m596R.put("object_name", name);
            Unit unit = Unit.INSTANCE;
            C0917a.m221e(c0917a, "system/track", Object.class, m596R, C0844f.f245c, null, false, false, null, false, 432);
            m174d(this, context, bean.link, null, null, 12);
        }

        /* renamed from: c */
        public final void m177c(@NotNull Context context, @NotNull NewAd bean) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(bean, "bean");
            String id = bean.f10022id;
            Intrinsics.checkNotNullExpressionValue(id, "bean.id");
            String name = bean.name;
            Intrinsics.checkNotNullExpressionValue(name, "bean.name");
            Intrinsics.checkNotNullParameter("ad", "type");
            Intrinsics.checkNotNullParameter(id, "id");
            Intrinsics.checkNotNullParameter(name, "name");
            C0917a c0917a = C0917a.f372a;
            HashMap m596R = C1499a.m596R("object_type", "ad", "object_id", id);
            m596R.put("object_name", name);
            Unit unit = Unit.INSTANCE;
            C0917a.m221e(c0917a, "system/track", Object.class, m596R, C0844f.f245c, null, false, false, null, false, 432);
            m174d(this, context, bean.link, null, null, 12);
        }
    }
}
