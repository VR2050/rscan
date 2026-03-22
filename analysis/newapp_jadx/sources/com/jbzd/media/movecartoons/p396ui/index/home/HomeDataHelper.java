package com.jbzd.media.movecartoons.p396ui.index.home;

import android.content.SharedPreferences;
import android.text.TextUtils;
import com.jbzd.media.movecartoons.bean.response.BuySuccessBean;
import com.jbzd.media.movecartoons.bean.response.CheckBean;
import com.jbzd.media.movecartoons.bean.response.FindBean;
import com.jbzd.media.movecartoons.bean.response.FoundPickBean;
import com.jbzd.media.movecartoons.bean.response.HomeBlockBean;
import com.jbzd.media.movecartoons.bean.response.HomeModuleBean;
import com.jbzd.media.movecartoons.bean.response.HomeTabBean1;
import com.jbzd.media.movecartoons.bean.response.HomeVideoGroupBean;
import com.jbzd.media.movecartoons.bean.response.VideoDetailBean;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.jbzd.media.movecartoons.bean.response.tag.TagLoveBean;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt__MutableCollectionsKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p146l.C1568e;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0096\u0001\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0010 \n\u0002\b\u0010\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0019\bÆ\u0002\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\bg\u0010hJ/\u0010\t\u001a\u0012\u0012\u0004\u0012\u00020\u00070\u0006j\b\u0012\u0004\u0012\u00020\u0007`\b2\b\u0010\u0003\u001a\u0004\u0018\u00010\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\t\u0010\nJI\u0010\u0011\u001a\u0012\u0012\u0004\u0012\u00020\u00070\u0006j\b\u0012\u0004\u0012\u00020\u0007`\b2\b\u0010\u0003\u001a\u0004\u0018\u00010\u00022\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\f\u001a\u00020\u000b2\b\u0010\u000e\u001a\u0004\u0018\u00010\r2\u0006\u0010\u0010\u001a\u00020\u000f¢\u0006\u0004\b\u0011\u0010\u0012J'\u0010\u0015\u001a\u0012\u0012\u0004\u0012\u00020\u00070\u0006j\b\u0012\u0004\u0012\u00020\u0007`\b2\b\u0010\u0014\u001a\u0004\u0018\u00010\u0013¢\u0006\u0004\b\u0015\u0010\u0016Jq\u0010$\u001a\u00020\u001e2\b\u0010\u0017\u001a\u0004\u0018\u00010\r2\b\u0010\u0018\u001a\u0004\u0018\u00010\r2%\b\u0002\u0010\u001f\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010\u001a¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\u001d\u0012\u0004\u0012\u00020\u001e0\u00192'\b\u0002\u0010#\u001a!\u0012\u0017\u0012\u00150 j\u0002`!¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u001e0\u0019¢\u0006\u0004\b$\u0010%J}\u0010'\u001a\u00020\u001e2\b\u0010\u0017\u001a\u0004\u0018\u00010\r2\b\u0010\u0018\u001a\u0004\u0018\u00010\r2\n\b\u0002\u0010&\u001a\u0004\u0018\u00010\r2%\b\u0002\u0010\u001f\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010\u0001¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\u001d\u0012\u0004\u0012\u00020\u001e0\u00192'\b\u0002\u0010#\u001a!\u0012\u0017\u0012\u00150 j\u0002`!¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u001e0\u0019¢\u0006\u0004\b'\u0010(Jg\u0010)\u001a\u00020\u001e2\b\u0010\u0017\u001a\u0004\u0018\u00010\r2%\b\u0002\u0010\u001f\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010\u001a¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\u001d\u0012\u0004\u0012\u00020\u001e0\u00192'\b\u0002\u0010#\u001a!\u0012\u0017\u0012\u00150 j\u0002`!¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u001e0\u0019¢\u0006\u0004\b)\u0010*Jg\u0010+\u001a\u00020\u001e2\b\u0010\u0017\u001a\u0004\u0018\u00010\r2%\b\u0002\u0010\u001f\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010\u0001¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\u001d\u0012\u0004\u0012\u00020\u001e0\u00192'\b\u0002\u0010#\u001a!\u0012\u0017\u0012\u00150 j\u0002`!¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u001e0\u0019¢\u0006\u0004\b+\u0010*J{\u0010-\u001a\u00020\u001e2\b\u0010\u0018\u001a\u0004\u0018\u00010\r2\b\u0010\u0017\u001a\u0004\u0018\u00010\r2\b\u0010,\u001a\u0004\u0018\u00010\r2%\b\u0002\u0010\u001f\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010\u001a¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\u001d\u0012\u0004\u0012\u00020\u001e0\u00192'\b\u0002\u0010#\u001a!\u0012\u0017\u0012\u00150 j\u0002`!¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u001e0\u0019¢\u0006\u0004\b-\u0010(J\u001b\u00100\u001a\b\u0012\u0004\u0012\u00020\r0/2\u0006\u0010.\u001a\u00020\u000b¢\u0006\u0004\b0\u00101J#\u00103\u001a\b\u0012\u0004\u0012\u00020\r0/2\u0006\u0010.\u001a\u00020\u000b2\u0006\u00102\u001a\u00020\u000b¢\u0006\u0004\b3\u00104Jq\u00105\u001a\u00020\u001e2\b\u0010\u0017\u001a\u0004\u0018\u00010\r2\b\u0010\u0018\u001a\u0004\u0018\u00010\r2%\b\u0002\u0010\u001f\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010\u0001¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\u001d\u0012\u0004\u0012\u00020\u001e0\u00192'\b\u0002\u0010#\u001a!\u0012\u0017\u0012\u00150 j\u0002`!¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u001e0\u0019¢\u0006\u0004\b5\u0010%J\r\u00106\u001a\u00020\u000b¢\u0006\u0004\b6\u00107J\u0015\u00109\u001a\u00020\r2\u0006\u00108\u001a\u00020\u000b¢\u0006\u0004\b9\u0010:J\u0015\u0010<\u001a\u00020\r2\u0006\u0010;\u001a\u00020\u000b¢\u0006\u0004\b<\u0010:J:\u0010>\u001a\u00020\u001e2\b\u0010\u0017\u001a\u0004\u0018\u00010\r2!\u0010\u001f\u001a\u001d\u0012\u0013\u0012\u00110\u000b¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(=\u0012\u0004\u0012\u00020\u001e0\u0019¢\u0006\u0004\b>\u0010?Jc\u0010A\u001a\u00020\u001e2\b\u0010\u0017\u001a\u0004\u0018\u00010\r2!\u0010\u001f\u001a\u001d\u0012\u0013\u0012\u00110@¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(=\u0012\u0004\u0012\u00020\u001e0\u00192'\b\u0002\u0010#\u001a!\u0012\u0017\u0012\u00150 j\u0002`!¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u001e0\u0019¢\u0006\u0004\bA\u0010*JZ\u0010D\u001a\u00020\u001e2\b\u0010,\u001a\u0004\u0018\u00010\r2\b\u0010B\u001a\u0004\u0018\u00010\r2\u000e\b\u0002\u0010\u001f\u001a\b\u0012\u0004\u0012\u00020\u001e0C2'\b\u0002\u0010#\u001a!\u0012\u0017\u0012\u00150 j\u0002`!¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u001e0\u0019¢\u0006\u0004\bD\u0010EJS\u0010K\u001a\u00020\u001e2\u0006\u0010\u0017\u001a\u00020\r2<\b\u0002\u0010J\u001a6\u0012\u0015\u0012\u0013\u0018\u00010\u000b¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(G\u0012\u0015\u0012\u0013\u0018\u00010H¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(I\u0012\u0004\u0012\u00020\u001e0F¢\u0006\u0004\bK\u0010LJS\u0010M\u001a\u00020\u001e2\u0006\u0010\u0017\u001a\u00020\r2<\b\u0002\u0010J\u001a6\u0012\u0015\u0012\u0013\u0018\u00010\u000b¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(G\u0012\u0015\u0012\u0013\u0018\u00010H¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(I\u0012\u0004\u0012\u00020\u001e0F¢\u0006\u0004\bM\u0010LJq\u0010Q\u001a\u00020\u001e2\u000e\u0010O\u001a\n\u0012\u0004\u0012\u00020N\u0018\u00010/2)\u0010\u001f\u001a%\u0012\u001b\u0012\u0019\u0012\u0004\u0012\u00020P\u0018\u00010/¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(=\u0012\u0004\u0012\u00020\u001e0\u00192'\b\u0002\u0010#\u001a!\u0012\u0017\u0012\u00150 j\u0002`!¢\u0006\f\b\u001b\u0012\b\b\u001c\u0012\u0004\b\b(\"\u0012\u0004\u0012\u00020\u001e0\u0019¢\u0006\u0004\bQ\u0010RJ'\u0010U\u001a\u00020\r2\b\u0010S\u001a\u0004\u0018\u00010\r2\u000e\u0010T\u001a\n\u0012\u0004\u0012\u00020P\u0018\u00010/¢\u0006\u0004\bU\u0010VJ!\u0010W\u001a\u00020\u001e2\b\u0010\u0017\u001a\u0004\u0018\u00010\r2\b\u0010\u0018\u001a\u0004\u0018\u00010\r¢\u0006\u0004\bW\u0010XR\u0016\u0010Y\u001a\u00020\r8\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\bY\u0010ZR\u0016\u0010[\u001a\u00020\r8\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b[\u0010ZR\u0016\u0010\\\u001a\u00020\r8\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\\\u0010ZR\u0016\u0010]\u001a\u00020\r8\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b]\u0010ZR\u0016\u0010^\u001a\u00020\r8\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b^\u0010ZR$\u0010_\u001a\u0004\u0018\u00010\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b_\u0010`\u001a\u0004\ba\u0010b\"\u0004\bc\u0010dR\u0016\u0010e\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\be\u0010f¨\u0006i"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/HomeDataHelper;", "", "Lcom/jbzd/media/movecartoons/bean/response/HomeTabBean1;", "tabInfoBean", "", "page", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/bean/response/HomeBlockBean;", "Lkotlin/collections/ArrayList;", "convertToList", "(Lcom/jbzd/media/movecartoons/bean/response/HomeTabBean1;I)Ljava/util/ArrayList;", "", "isModulePage", "", "link", "Lcom/jbzd/media/movecartoons/ui/index/home/HomeListFragment;", "fragment", "convertToListV2", "(Lcom/jbzd/media/movecartoons/bean/response/HomeTabBean1;IZLjava/lang/String;Lcom/jbzd/media/movecartoons/ui/index/home/HomeListFragment;)Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/bean/response/FoundPickBean;", "foundPickBean", "convertToPickList", "(Lcom/jbzd/media/movecartoons/bean/response/FoundPickBean;)Ljava/util/ArrayList;", "id", "type", "Lkotlin/Function1;", "Lcom/jbzd/media/movecartoons/bean/response/CheckBean;", "Lkotlin/ParameterName;", "name", "response", "", FindBean.status_success, "Ljava/lang/Exception;", "Lkotlin/Exception;", C1568e.f1949a, "error", "checkLove", "(Ljava/lang/String;Ljava/lang/String;Lkotlin/jvm/functions/Function1;Lkotlin/jvm/functions/Function1;)V", "canvas", "doLove", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/jvm/functions/Function1;Lkotlin/jvm/functions/Function1;)V", "checkFollow", "(Ljava/lang/String;Lkotlin/jvm/functions/Function1;Lkotlin/jvm/functions/Function1;)V", "doFollow", "userId", "checkFollowAndLove", "isLove", "", "getVideoOptionItems", "(Z)Ljava/util/List;", "isFollow", "getUserOptionItemsWithVideo", "(ZZ)Ljava/util/List;", "doZan", "getNeedShowThreeAd", "()Z", "has", "getRequestHasImage", "(Z)Ljava/lang/String;", "dislike", "getRequestDislike", "t", "doBuyMovie", "(Ljava/lang/String;Lkotlin/jvm/functions/Function1;)V", "Lcom/jbzd/media/movecartoons/bean/response/BuySuccessBean;", "doBuyImages", "price", "Lkotlin/Function0;", "doBuyFans", "(Ljava/lang/String;Ljava/lang/String;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function1;)V", "Lkotlin/Function2;", "isSuccess", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;", "video", "hideLoading", "loadMovieDetail", "(Ljava/lang/String;Lkotlin/jvm/functions/Function2;)V", "loadImagesDetail", "Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;", "tags", "Lcom/jbzd/media/movecartoons/bean/response/tag/TagLoveBean;", "checkTagsLove", "(Ljava/util/List;Lkotlin/jvm/functions/Function1;Lkotlin/jvm/functions/Function1;)V", "tagId", "loveList", "getTagLoveById", "(Ljava/lang/String;Ljava/util/List;)Ljava/lang/String;", "doDislike", "(Ljava/lang/String;Ljava/lang/String;)V", "key_need_three_ad", "Ljava/lang/String;", "type_video", "type_group", "type_tag", "type_imgs", "firstPageBean", "Lcom/jbzd/media/movecartoons/bean/response/HomeTabBean1;", "getFirstPageBean", "()Lcom/jbzd/media/movecartoons/bean/response/HomeTabBean1;", "setFirstPageBean", "(Lcom/jbzd/media/movecartoons/bean/response/HomeTabBean1;)V", "count_interval", "I", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class HomeDataHelper {

    @NotNull
    public static final HomeDataHelper INSTANCE = new HomeDataHelper();
    public static final int count_interval = 6;

    @Nullable
    private static HomeTabBean1 firstPageBean = null;

    @NotNull
    public static final String key_need_three_ad = "need_three_ad";

    @NotNull
    public static final String type_group = "3";

    @NotNull
    public static final String type_imgs = "2";

    @NotNull
    public static final String type_tag = "4";

    @NotNull
    public static final String type_video = "1";

    private HomeDataHelper() {
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void checkFollow$default(HomeDataHelper homeDataHelper, String str, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            function1 = new Function1<CheckBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$checkFollow$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(CheckBean checkBean) {
                    invoke2(checkBean);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable CheckBean checkBean) {
                }
            };
        }
        if ((i2 & 4) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$checkFollow$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        homeDataHelper.checkFollow(str, function1, function12);
    }

    public static /* synthetic */ void checkFollowAndLove$default(HomeDataHelper homeDataHelper, String str, String str2, String str3, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 8) != 0) {
            function1 = new Function1<CheckBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$checkFollowAndLove$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(CheckBean checkBean) {
                    invoke2(checkBean);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable CheckBean checkBean) {
                }
            };
        }
        Function1 function13 = function1;
        if ((i2 & 16) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$checkFollowAndLove$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        homeDataHelper.checkFollowAndLove(str, str2, str3, function13, function12);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void checkLove$default(HomeDataHelper homeDataHelper, String str, String str2, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            function1 = new Function1<CheckBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$checkLove$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(CheckBean checkBean) {
                    invoke2(checkBean);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable CheckBean checkBean) {
                }
            };
        }
        if ((i2 & 8) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$checkLove$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        homeDataHelper.checkLove(str, str2, function1, function12);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void checkTagsLove$default(HomeDataHelper homeDataHelper, List list, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$checkTagsLove$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        homeDataHelper.checkTagsLove(list, function1, function12);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void doBuyFans$default(HomeDataHelper homeDataHelper, String str, String str2, Function0 function0, Function1 function1, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            function0 = new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$doBuyFans$1
                @Override // kotlin.jvm.functions.Function0
                public /* bridge */ /* synthetic */ Unit invoke() {
                    invoke2();
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2() {
                }
            };
        }
        if ((i2 & 8) != 0) {
            function1 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$doBuyFans$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        homeDataHelper.doBuyFans(str, str2, function0, function1);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void doBuyImages$default(HomeDataHelper homeDataHelper, String str, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$doBuyImages$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        homeDataHelper.doBuyImages(str, function1, function12);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void doFollow$default(HomeDataHelper homeDataHelper, String str, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            function1 = new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$doFollow$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Object obj2) {
                    invoke2(obj2);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Object obj2) {
                }
            };
        }
        if ((i2 & 4) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$doFollow$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        homeDataHelper.doFollow(str, function1, function12);
    }

    public static /* synthetic */ void doLove$default(HomeDataHelper homeDataHelper, String str, String str2, String str3, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            str3 = null;
        }
        String str4 = str3;
        if ((i2 & 8) != 0) {
            function1 = new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$doLove$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Object obj2) {
                    invoke2(obj2);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Object obj2) {
                }
            };
        }
        Function1 function13 = function1;
        if ((i2 & 16) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$doLove$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        homeDataHelper.doLove(str, str2, str4, function13, function12);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void doZan$default(HomeDataHelper homeDataHelper, String str, String str2, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            function1 = new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$doZan$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Object obj2) {
                    invoke2(obj2);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Object obj2) {
                }
            };
        }
        if ((i2 & 8) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$doZan$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        homeDataHelper.doZan(str, str2, function1, function12);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void loadImagesDetail$default(HomeDataHelper homeDataHelper, String str, Function2 function2, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            function2 = new Function2<Boolean, VideoDetailBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$loadImagesDetail$1
                @Override // kotlin.jvm.functions.Function2
                public /* bridge */ /* synthetic */ Unit invoke(Boolean bool, VideoDetailBean videoDetailBean) {
                    invoke2(bool, videoDetailBean);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Boolean bool, @Nullable VideoDetailBean videoDetailBean) {
                }
            };
        }
        homeDataHelper.loadImagesDetail(str, function2);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void loadMovieDetail$default(HomeDataHelper homeDataHelper, String str, Function2 function2, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            function2 = new Function2<Boolean, VideoDetailBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$loadMovieDetail$1
                @Override // kotlin.jvm.functions.Function2
                public /* bridge */ /* synthetic */ Unit invoke(Boolean bool, VideoDetailBean videoDetailBean) {
                    invoke2(bool, videoDetailBean);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Boolean bool, @Nullable VideoDetailBean videoDetailBean) {
                }
            };
        }
        homeDataHelper.loadMovieDetail(str, function2);
    }

    public final void checkFollow(@Nullable String id, @NotNull Function1<? super CheckBean, Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        if (id == null) {
            id = "";
        }
        hashMap.put("follow_id", id);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "video/checkState", CheckBean.class, hashMap, success, error, false, false, null, false, 480);
    }

    public final void checkFollowAndLove(@Nullable String type, @Nullable String id, @Nullable String userId, @NotNull Function1<? super CheckBean, Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("type", type == null ? "" : type);
        hashMap.put("love_id", id == null ? "" : id);
        hashMap.put("follow_id", userId != null ? userId : "");
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "video/checkState", CheckBean.class, hashMap, success, error, false, false, null, false, 480);
    }

    public final void checkLove(@Nullable String id, @Nullable String type, @NotNull Function1<? super CheckBean, Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("love_id", id == null ? "" : id);
        hashMap.put("type", type != null ? type : "");
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "video/checkState", CheckBean.class, hashMap, success, error, false, false, null, false, 480);
    }

    public final void checkTagsLove(@Nullable List<? extends TagBean> tags, @NotNull Function1<? super List<? extends TagLoveBean>, Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        String joinToString$default = tags == null ? null : CollectionsKt___CollectionsKt.joinToString$default(tags, ChineseToPinyinResource.Field.COMMA, null, null, 0, null, new Function1<TagBean, CharSequence>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$checkTagsLove$tagIds$1
            @Override // kotlin.jvm.functions.Function1
            @NotNull
            public final CharSequence invoke(@NotNull TagBean it) {
                Intrinsics.checkNotNullParameter(it, "it");
                String str = it.f10032id;
                Intrinsics.checkNotNullExpressionValue(str, "it.id");
                return str;
            }
        }, 30, null);
        if (joinToString$default == null || joinToString$default.length() == 0) {
            return;
        }
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("tag_ids", joinToString$default);
        Unit unit = Unit.INSTANCE;
        C0917a.m222f(c0917a, "video/isLove", TagLoveBean.class, m595Q, success, error, false, false, null, false, 416);
    }

    @NotNull
    public final ArrayList<HomeBlockBean> convertToList(@Nullable HomeTabBean1 tabInfoBean, int page) {
        List<HomeVideoGroupBean> list;
        int i2;
        int i3;
        ArrayList<HomeBlockBean> arrayList = new ArrayList<>();
        if (tabInfoBean == null) {
            return arrayList;
        }
        if (page < 2) {
            firstPageBean = tabInfoBean;
            List<HomeModuleBean> list2 = tabInfoBean.modules;
            if (list2 != null) {
                for (HomeModuleBean homeModuleBean : list2) {
                    HomeBlockBean homeBlockBean = new HomeBlockBean();
                    homeBlockBean.style = homeModuleBean.getBlockStyle();
                    homeBlockBean.module = homeModuleBean;
                    Unit unit = Unit.INSTANCE;
                    arrayList.add(homeBlockBean);
                }
            }
            List<VideoItemBean> list3 = tabInfoBean.long_video;
            if (list3 != null) {
                for (VideoItemBean videoItemBean : list3) {
                    HomeBlockBean homeBlockBean2 = new HomeBlockBean();
                    homeBlockBean2.style = videoItemBean.getIsAd() ? 1 : 4;
                    homeBlockBean2.long_video = videoItemBean;
                    Unit unit2 = Unit.INSTANCE;
                    arrayList.add(homeBlockBean2);
                }
            }
            List<HomeVideoGroupBean> shortGroups = tabInfoBean.short_video_group;
            if (!(shortGroups == null || shortGroups.isEmpty())) {
                HomeBlockBean homeBlockBean3 = new HomeBlockBean();
                homeBlockBean3.style = 3;
                Intrinsics.checkNotNullExpressionValue(shortGroups, "shortGroups");
                homeBlockBean3.short_video_group = (HomeVideoGroupBean) CollectionsKt___CollectionsKt.first((List) shortGroups);
                Unit unit3 = Unit.INSTANCE;
                arrayList.add(homeBlockBean3);
            }
            List<VideoItemBean> list4 = tabInfoBean.short_video;
            if (list4 != null && list4.size() > 0) {
                Iterator<T> it = list4.iterator();
                while (it.hasNext()) {
                    ((VideoItemBean) it.next()).realPage = (page + 1) / 2;
                }
                HomeBlockBean homeBlockBean4 = new HomeBlockBean();
                homeBlockBean4.style = 5;
                homeBlockBean4.short_videos = list4;
                homeBlockBean4.realPage = (page + 1) / 2;
                Unit unit4 = Unit.INSTANCE;
                arrayList.add(homeBlockBean4);
            }
        } else {
            List<VideoItemBean> list5 = tabInfoBean.long_video;
            if (list5 != null) {
                for (VideoItemBean videoItemBean2 : list5) {
                    HomeBlockBean homeBlockBean5 = new HomeBlockBean();
                    homeBlockBean5.style = videoItemBean2.getIsAd() ? 1 : 4;
                    homeBlockBean5.long_video = videoItemBean2;
                    Unit unit5 = Unit.INSTANCE;
                    arrayList.add(homeBlockBean5);
                }
            }
            if (page % 2 == 0) {
                HomeTabBean1 homeTabBean1 = firstPageBean;
                list = homeTabBean1 != null ? homeTabBean1.long_video_group : null;
                if (!(list == null || list.isEmpty()) && list.size() > (i3 = (page / 2) - 1)) {
                    HomeBlockBean homeBlockBean6 = new HomeBlockBean();
                    homeBlockBean6.style = 2;
                    homeBlockBean6.long_video_group = list.get(i3);
                    Unit unit6 = Unit.INSTANCE;
                    arrayList.add(homeBlockBean6);
                }
            } else {
                HomeTabBean1 homeTabBean12 = firstPageBean;
                list = homeTabBean12 != null ? homeTabBean12.short_video_group : null;
                if (!(list == null || list.isEmpty()) && list.size() > (i2 = page / 2)) {
                    HomeBlockBean homeBlockBean7 = new HomeBlockBean();
                    homeBlockBean7.style = 3;
                    homeBlockBean7.short_video_group = list.get(i2);
                    Unit unit7 = Unit.INSTANCE;
                    arrayList.add(homeBlockBean7);
                }
                List<VideoItemBean> list6 = tabInfoBean.short_video;
                if (list6 != null && list6.size() > 0) {
                    Iterator<T> it2 = list6.iterator();
                    while (it2.hasNext()) {
                        ((VideoItemBean) it2.next()).realPage = (page + 1) / 2;
                    }
                    HomeBlockBean homeBlockBean8 = new HomeBlockBean();
                    homeBlockBean8.style = 5;
                    homeBlockBean8.short_videos = list6;
                    Unit unit8 = Unit.INSTANCE;
                    arrayList.add(homeBlockBean8);
                }
            }
        }
        return arrayList;
    }

    @NotNull
    public final ArrayList<HomeBlockBean> convertToListV2(@Nullable HomeTabBean1 tabInfoBean, int page, boolean isModulePage, @Nullable String link, @NotNull HomeListFragment fragment) {
        List<HomeVideoGroupBean> list;
        int i2;
        int i3;
        List<HomeModuleBean> list2;
        Intrinsics.checkNotNullParameter(fragment, "fragment");
        ArrayList<HomeBlockBean> arrayList = new ArrayList<>();
        if (tabInfoBean == null) {
            return arrayList;
        }
        if (page < 2) {
            firstPageBean = tabInfoBean;
            List<HomeModuleBean> list3 = tabInfoBean.modules;
            if (list3 != null) {
                for (HomeModuleBean homeModuleBean : list3) {
                    HomeBlockBean homeBlockBean = new HomeBlockBean();
                    homeBlockBean.style = homeModuleBean.getBlockStyle();
                    homeBlockBean.module = homeModuleBean;
                    Unit unit = Unit.INSTANCE;
                    arrayList.add(homeBlockBean);
                }
                Unit unit2 = Unit.INSTANCE;
            }
            List<VideoItemBean> longVideos = tabInfoBean.long_video;
            if (!(longVideos == null || longVideos.isEmpty())) {
                if (!fragment.getHasShowMoreGood() && !Intrinsics.areEqual(link, "hide")) {
                    HomeBlockBean homeBlockBean2 = new HomeBlockBean();
                    homeBlockBean2.style = 0;
                    fragment.setHasShowMoreGood(true);
                    Unit unit3 = Unit.INSTANCE;
                    arrayList.add(homeBlockBean2);
                }
                Intrinsics.checkNotNullExpressionValue(longVideos, "longVideos");
                VideoItemBean videoItemBean = (VideoItemBean) CollectionsKt___CollectionsKt.last((List) longVideos);
                if (videoItemBean.getIsAd()) {
                    CollectionsKt__MutableCollectionsKt.removeLast(longVideos);
                }
                ArrayList arrayList2 = new ArrayList();
                Iterator<VideoItemBean> it = longVideos.iterator();
                int i4 = 0;
                while (it.hasNext()) {
                    int i5 = i4 + 1;
                    arrayList2.add(it.next());
                    if (i4 % 2 == 1) {
                        HomeBlockBean homeBlockBean3 = new HomeBlockBean();
                        homeBlockBean3.style = 4;
                        homeBlockBean3.isLastTwoLongs = i4 / 2 == (longVideos.size() / 2) - 1;
                        homeBlockBean3.home_long_videos = arrayList2;
                        Unit unit4 = Unit.INSTANCE;
                        arrayList.add(homeBlockBean3);
                        arrayList2 = new ArrayList();
                    }
                    i4 = i5;
                }
                if (videoItemBean.getIsAd()) {
                    HomeBlockBean homeBlockBean4 = new HomeBlockBean();
                    homeBlockBean4.style = 1;
                    homeBlockBean4.long_video = videoItemBean;
                    Unit unit5 = Unit.INSTANCE;
                    arrayList.add(homeBlockBean4);
                }
            }
            List<HomeVideoGroupBean> shortGroups = tabInfoBean.short_video_group;
            if (!(shortGroups == null || shortGroups.isEmpty())) {
                HomeBlockBean homeBlockBean5 = new HomeBlockBean();
                homeBlockBean5.style = 3;
                Intrinsics.checkNotNullExpressionValue(shortGroups, "shortGroups");
                homeBlockBean5.short_video_group = (HomeVideoGroupBean) CollectionsKt___CollectionsKt.first((List) shortGroups);
                Unit unit6 = Unit.INSTANCE;
                arrayList.add(homeBlockBean5);
            }
            List<VideoItemBean> list4 = tabInfoBean.short_video;
            if (list4 != null) {
                if (list4.size() > 0) {
                    Iterator<T> it2 = list4.iterator();
                    while (it2.hasNext()) {
                        ((VideoItemBean) it2.next()).realPage = (page + 1) / 2;
                    }
                    HomeBlockBean homeBlockBean6 = new HomeBlockBean();
                    homeBlockBean6.style = 5;
                    homeBlockBean6.short_videos = list4;
                    homeBlockBean6.realPage = (page + 1) / 2;
                    Unit unit7 = Unit.INSTANCE;
                    arrayList.add(homeBlockBean6);
                }
                Unit unit8 = Unit.INSTANCE;
            }
        } else {
            if (isModulePage && (list2 = tabInfoBean.modules) != null) {
                for (HomeModuleBean homeModuleBean2 : list2) {
                    HomeBlockBean homeBlockBean7 = new HomeBlockBean();
                    homeBlockBean7.style = homeModuleBean2.getBlockStyle();
                    homeBlockBean7.module = homeModuleBean2;
                    Unit unit9 = Unit.INSTANCE;
                    arrayList.add(homeBlockBean7);
                }
                Unit unit10 = Unit.INSTANCE;
            }
            List<VideoItemBean> longVideos2 = tabInfoBean.long_video;
            if (!(longVideos2 == null || longVideos2.isEmpty())) {
                if (!fragment.getHasShowMoreGood() && !Intrinsics.areEqual(link, "hide")) {
                    HomeBlockBean homeBlockBean8 = new HomeBlockBean();
                    homeBlockBean8.style = 0;
                    fragment.setHasShowMoreGood(true);
                    Unit unit11 = Unit.INSTANCE;
                    arrayList.add(homeBlockBean8);
                }
                Intrinsics.checkNotNullExpressionValue(longVideos2, "longVideos");
                VideoItemBean videoItemBean2 = (VideoItemBean) CollectionsKt___CollectionsKt.last((List) longVideos2);
                if (videoItemBean2.getIsAd()) {
                    CollectionsKt__MutableCollectionsKt.removeLast(longVideos2);
                }
                ArrayList arrayList3 = new ArrayList();
                Iterator<VideoItemBean> it3 = longVideos2.iterator();
                int i6 = 0;
                while (it3.hasNext()) {
                    int i7 = i6 + 1;
                    arrayList3.add(it3.next());
                    if (i6 % 2 == 1) {
                        HomeBlockBean homeBlockBean9 = new HomeBlockBean();
                        homeBlockBean9.style = 4;
                        homeBlockBean9.isLastTwoLongs = i6 / 2 == (longVideos2.size() / 2) - 1;
                        homeBlockBean9.home_long_videos = arrayList3;
                        Unit unit12 = Unit.INSTANCE;
                        arrayList.add(homeBlockBean9);
                        arrayList3 = new ArrayList();
                    }
                    i6 = i7;
                }
                if (videoItemBean2.getIsAd()) {
                    HomeBlockBean homeBlockBean10 = new HomeBlockBean();
                    homeBlockBean10.style = 1;
                    homeBlockBean10.long_video = videoItemBean2;
                    Unit unit13 = Unit.INSTANCE;
                    arrayList.add(homeBlockBean10);
                }
            }
            if (page % 2 == 0) {
                HomeTabBean1 homeTabBean1 = firstPageBean;
                list = homeTabBean1 != null ? homeTabBean1.long_video_group : null;
                if (!(list == null || list.isEmpty()) && list.size() > (i3 = (page / 2) - 1)) {
                    HomeBlockBean homeBlockBean11 = new HomeBlockBean();
                    homeBlockBean11.style = 2;
                    homeBlockBean11.long_video_group = list.get(i3);
                    Unit unit14 = Unit.INSTANCE;
                    arrayList.add(homeBlockBean11);
                }
            } else {
                HomeTabBean1 homeTabBean12 = firstPageBean;
                list = homeTabBean12 != null ? homeTabBean12.short_video_group : null;
                if (!(list == null || list.isEmpty()) && list.size() > (i2 = page / 2)) {
                    HomeBlockBean homeBlockBean12 = new HomeBlockBean();
                    homeBlockBean12.style = 3;
                    homeBlockBean12.short_video_group = list.get(i2);
                    Unit unit15 = Unit.INSTANCE;
                    arrayList.add(homeBlockBean12);
                }
                List<VideoItemBean> list5 = tabInfoBean.short_video;
                if (list5 != null) {
                    if (list5.size() > 0) {
                        Iterator<T> it4 = list5.iterator();
                        while (it4.hasNext()) {
                            ((VideoItemBean) it4.next()).realPage = (page + 1) / 2;
                        }
                        HomeBlockBean homeBlockBean13 = new HomeBlockBean();
                        homeBlockBean13.style = 5;
                        homeBlockBean13.short_videos = list5;
                        homeBlockBean13.realPage = (page + 1) / 2;
                        Unit unit16 = Unit.INSTANCE;
                        arrayList.add(homeBlockBean13);
                    }
                    Unit unit17 = Unit.INSTANCE;
                }
            }
        }
        return arrayList;
    }

    @NotNull
    public final ArrayList<HomeBlockBean> convertToPickList(@Nullable FoundPickBean foundPickBean) {
        ArrayList<HomeBlockBean> arrayList = new ArrayList<>();
        if (foundPickBean == null) {
            return arrayList;
        }
        List<VideoItemBean> list = foundPickBean.long_video;
        if (list != null) {
            HomeBlockBean homeBlockBean = new HomeBlockBean();
            homeBlockBean.style = 4;
            homeBlockBean.long_videos = list;
            homeBlockBean.pickBean = foundPickBean;
            Unit unit = Unit.INSTANCE;
            arrayList.add(homeBlockBean);
        }
        List<VideoItemBean> list2 = foundPickBean.short_video;
        if (list2 != null && list2.size() > 0) {
            HomeBlockBean homeBlockBean2 = new HomeBlockBean();
            homeBlockBean2.style = 5;
            homeBlockBean2.short_videos = list2;
            homeBlockBean2.pickBean = foundPickBean;
            Unit unit2 = Unit.INSTANCE;
            arrayList.add(homeBlockBean2);
        }
        HomeVideoGroupBean homeVideoGroupBean = foundPickBean.video_group;
        if (homeVideoGroupBean != null) {
            Boolean isLongGroup = homeVideoGroupBean.isLongGroup();
            Intrinsics.checkNotNullExpressionValue(isLongGroup, "group.isLongGroup");
            if (isLongGroup.booleanValue()) {
                HomeBlockBean homeBlockBean3 = new HomeBlockBean();
                homeBlockBean3.style = 2;
                homeBlockBean3.long_video_group = homeVideoGroupBean;
                homeBlockBean3.pickBean = foundPickBean;
                Unit unit3 = Unit.INSTANCE;
                arrayList.add(homeBlockBean3);
            } else {
                HomeBlockBean homeBlockBean4 = new HomeBlockBean();
                homeBlockBean4.style = 3;
                homeBlockBean4.short_video_group = homeVideoGroupBean;
                homeBlockBean4.pickBean = foundPickBean;
                Unit unit4 = Unit.INSTANCE;
                arrayList.add(homeBlockBean4);
            }
        }
        return arrayList;
    }

    public final void doBuyFans(@Nullable String userId, @Nullable String price, @NotNull final Function0<Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        HashMap hashMap = new HashMap();
        hashMap.put("user_id", userId == null ? "" : userId);
        hashMap.put("price", price != null ? price : "");
        C0917a.m221e(C0917a.f372a, "videoAnchor/buy", Object.class, hashMap, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$doBuyFans$4
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                invoke2(obj);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable Object obj) {
                success.invoke();
                MineViewModel.INSTANCE.getUserInfo();
            }
        }, error, false, false, null, false, 480);
    }

    public final void doBuyImages(@Nullable String id, @NotNull final Function1<? super BuySuccessBean, Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        if (id == null) {
            id = "";
        }
        hashMap.put("id", id);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "photoAlbum/buy", BuySuccessBean.class, hashMap, new Function1<BuySuccessBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$doBuyImages$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(BuySuccessBean buySuccessBean) {
                invoke2(buySuccessBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable BuySuccessBean buySuccessBean) {
                if (buySuccessBean != null) {
                    success.invoke(buySuccessBean);
                }
                MineViewModel.INSTANCE.getUserInfo();
            }
        }, error, false, false, null, false, 480);
    }

    public final void doBuyMovie(@Nullable String id, @NotNull final Function1<? super Boolean, Unit> success) {
        Intrinsics.checkNotNullParameter(success, "success");
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        if (id == null) {
            id = "";
        }
        hashMap.put("id", id);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "movie/doBuy", BuySuccessBean.class, hashMap, new Function1<BuySuccessBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$doBuyMovie$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(BuySuccessBean buySuccessBean) {
                invoke2(buySuccessBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable BuySuccessBean buySuccessBean) {
                C2354n.m2409L1("购买成功");
                success.invoke(Boolean.TRUE);
                MineViewModel.INSTANCE.getUserInfo();
            }
        }, null, false, false, null, false, 496);
    }

    public final void doDislike(@Nullable String id, @Nullable String type) {
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        if (id == null) {
            id = "";
        }
        hashMap.put("id", id);
        if (type == null) {
            type = "";
        }
        hashMap.put("type", type);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "video/dislike", Object.class, hashMap, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$doDislike$2
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                invoke2(obj);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable Object obj) {
            }
        }, null, false, false, null, false, 432);
    }

    public final void doFollow(@Nullable String id, @NotNull Function1<Object, Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        if (id == null) {
            id = "";
        }
        hashMap.put("user_id", id);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "video/favoriteCreator", Object.class, hashMap, success, error, false, false, null, false, 480);
    }

    public final void doLove(@Nullable String id, @Nullable String type, @Nullable String canvas, @NotNull Function1<Object, Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("id", id == null ? "" : id);
        if (!TextUtils.isEmpty(canvas)) {
            hashMap.put("canvas", canvas != null ? canvas : "");
        }
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "movie/doFavorite", Object.class, hashMap, success, error, false, false, null, false, 480);
    }

    public final void doZan(@Nullable String id, @Nullable String type, @NotNull Function1<Object, Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        if (id == null) {
            id = "";
        }
        hashMap.put("id", id);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "movie/doLove", Object.class, hashMap, success, error, false, false, null, false, 480);
    }

    @Nullable
    public final HomeTabBean1 getFirstPageBean() {
        return firstPageBean;
    }

    public final boolean getNeedShowThreeAd() {
        Intrinsics.checkNotNullParameter(key_need_three_ad, "key");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        int i2 = sharedPreferences.getInt(key_need_three_ad, 0) + 1;
        Intrinsics.checkNotNullParameter(key_need_three_ad, "key");
        ApplicationC2828a applicationC2828a2 = C2827a.f7670a;
        if (applicationC2828a2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences2 = applicationC2828a2.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences2, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        SharedPreferences.Editor editor = sharedPreferences2.edit();
        Intrinsics.checkExpressionValueIsNotNull(editor, "editor");
        editor.putInt(key_need_three_ad, i2);
        editor.commit();
        return i2 % 6 == 0;
    }

    @NotNull
    public final String getRequestDislike(boolean dislike) {
        return dislike ? "1" : "0";
    }

    @NotNull
    public final String getRequestHasImage(boolean has) {
        return has ? "1" : "0";
    }

    @NotNull
    public final String getTagLoveById(@Nullable String tagId, @Nullable List<? extends TagLoveBean> loveList) {
        if (tagId == null || tagId.length() == 0) {
            return "";
        }
        if (loveList == null || loveList.isEmpty()) {
            return "";
        }
        for (TagLoveBean tagLoveBean : loveList) {
            if (TextUtils.equals(tagLoveBean.f10033id, tagId)) {
                String str = tagLoveBean.is_love;
                Intrinsics.checkNotNullExpressionValue(str, "love.is_love");
                return str;
            }
        }
        return "";
    }

    @NotNull
    public final List<String> getUserOptionItemsWithVideo(boolean isLove, boolean isFollow) {
        return isLove ? isFollow ? CollectionsKt__CollectionsKt.arrayListOf("不感兴趣", "取消收藏", "已关注") : CollectionsKt__CollectionsKt.arrayListOf("不感兴趣", "取消收藏", "关注TA") : isFollow ? CollectionsKt__CollectionsKt.arrayListOf("不感兴趣", "加入收藏", "已关注") : CollectionsKt__CollectionsKt.arrayListOf("不感兴趣", "加入收藏", "关注TA");
    }

    @NotNull
    public final List<String> getVideoOptionItems(boolean isLove) {
        return isLove ? CollectionsKt__CollectionsKt.arrayListOf("不感兴趣", "取消收藏") : CollectionsKt__CollectionsKt.arrayListOf("不感兴趣", "加入收藏");
    }

    public final void loadImagesDetail(@NotNull String id, @NotNull final Function2<? super Boolean, ? super VideoDetailBean, Unit> hideLoading) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(hideLoading, "hideLoading");
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("id", id);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "photoAlbum/info", VideoDetailBean.class, hashMap, new Function1<VideoDetailBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$loadImagesDetail$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(VideoDetailBean videoDetailBean) {
                invoke2(videoDetailBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable VideoDetailBean videoDetailBean) {
                hideLoading.invoke(Boolean.TRUE, videoDetailBean);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$loadImagesDetail$4
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                hideLoading.invoke(Boolean.FALSE, null);
            }
        }, false, false, null, false, 480);
    }

    public final void loadMovieDetail(@NotNull String id, @NotNull final Function2<? super Boolean, ? super VideoDetailBean, Unit> hideLoading) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(hideLoading, "hideLoading");
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("id", id);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "movie/detail", VideoDetailBean.class, hashMap, new Function1<VideoDetailBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$loadMovieDetail$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(VideoDetailBean videoDetailBean) {
                invoke2(videoDetailBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable VideoDetailBean videoDetailBean) {
                hideLoading.invoke(Boolean.TRUE, videoDetailBean);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.HomeDataHelper$loadMovieDetail$4
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                hideLoading.invoke(Boolean.FALSE, null);
            }
        }, false, false, null, false, 480);
    }

    public final void setFirstPageBean(@Nullable HomeTabBean1 homeTabBean1) {
        firstPageBean = homeTabBean1;
    }
}
