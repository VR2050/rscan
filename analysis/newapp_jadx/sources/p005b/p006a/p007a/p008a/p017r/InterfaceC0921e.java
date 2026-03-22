package p005b.p006a.p007a.p008a.p017r;

import androidx.exifinterface.media.ExifInterface;
import com.jbzd.media.movecartoons.bean.TokenBean;
import com.jbzd.media.movecartoons.bean.request.ChatRequest;
import com.jbzd.media.movecartoons.bean.response.ChatMsgBean;
import com.jbzd.media.movecartoons.bean.response.ExchangeLogBean;
import com.jbzd.media.movecartoons.bean.response.FollowItem;
import com.jbzd.media.movecartoons.bean.response.HeadImageBean;
import com.jbzd.media.movecartoons.bean.response.IncomeLogBean;
import com.jbzd.media.movecartoons.bean.response.PayBean;
import com.jbzd.media.movecartoons.bean.response.PicVefBean;
import com.jbzd.media.movecartoons.bean.response.PostListBean;
import com.jbzd.media.movecartoons.bean.response.RechargeBean;
import com.jbzd.media.movecartoons.bean.response.ShareBean;
import com.jbzd.media.movecartoons.bean.response.ShareInfoBean;
import com.jbzd.media.movecartoons.bean.response.UserFollowResponse;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.bean.response.VipInfoBean;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.ComicsItemBean;
import com.jbzd.media.movecartoons.bean.response.novel.NovelItemsBean;
import java.util.HashMap;
import java.util.List;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p143g.p144a.p146l.C1568e;
import p005b.p310s.p311a.C2743m;
import p379c.p380a.p383b2.InterfaceC3006b;
import p505n.p506e0.InterfaceC4986a;
import p505n.p506e0.InterfaceC4988c;
import p505n.p506e0.InterfaceC4990e;
import p505n.p506e0.InterfaceC5000o;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000¸\u0001\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\bf\u0018\u00002\u00020\u0001J\u0015\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00030\u0002H'¢\u0006\u0004\b\u0004\u0010\u0005J\u001b\u0010\b\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00070\u00060\u0002H'¢\u0006\u0004\b\b\u0010\u0005J\u001f\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000b0\u00022\b\b\u0001\u0010\n\u001a\u00020\tH'¢\u0006\u0004\b\f\u0010\rJ\u0015\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u000e0\u0002H'¢\u0006\u0004\b\u000f\u0010\u0005J7\u0010\u0015\u001a\b\u0012\u0004\u0012\u00020\u00140\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u00102\n\b\u0003\u0010\u0012\u001a\u0004\u0018\u00010\t2\n\b\u0003\u0010\u0013\u001a\u0004\u0018\u00010\tH'¢\u0006\u0004\b\u0015\u0010\u0016J\u001f\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\u00010\u00022\b\b\u0001\u0010\u0018\u001a\u00020\u0017H'¢\u0006\u0004\b\u0019\u0010\u001aJ\u0015\u0010\u001c\u001a\b\u0012\u0004\u0012\u00020\u001b0\u0002H'¢\u0006\u0004\b\u001c\u0010\u0005J)\u0010\u001f\u001a\b\u0012\u0004\u0012\u00020\u00010\u00022\b\b\u0001\u0010\u001d\u001a\u00020\t2\b\b\u0001\u0010\u001e\u001a\u00020\tH'¢\u0006\u0004\b\u001f\u0010 J%\u0010\"\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020!0\u00060\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u0010H'¢\u0006\u0004\b\"\u0010#J%\u0010%\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020$0\u00060\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u0010H'¢\u0006\u0004\b%\u0010#J%\u0010&\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020!0\u00060\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u0010H'¢\u0006\u0004\b&\u0010#J%\u0010'\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020$0\u00060\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u0010H'¢\u0006\u0004\b'\u0010#J%\u0010(\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020$0\u00060\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u0010H'¢\u0006\u0004\b(\u0010#J%\u0010)\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020!0\u00060\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u0010H'¢\u0006\u0004\b)\u0010#J%\u0010+\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020*0\u00060\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u0010H'¢\u0006\u0004\b+\u0010#J\u001f\u0010-\u001a\b\u0012\u0004\u0012\u00020\u00010\u00022\b\b\u0001\u0010,\u001a\u00020\tH'¢\u0006\u0004\b-\u0010\rJ)\u00101\u001a\b\u0012\u0004\u0012\u0002000\u00022\b\b\u0001\u0010.\u001a\u00020\t2\b\b\u0001\u0010/\u001a\u00020\tH'¢\u0006\u0004\b1\u0010 J)\u00102\u001a\b\u0012\u0004\u0012\u0002000\u00022\b\b\u0001\u0010.\u001a\u00020\t2\b\b\u0001\u0010/\u001a\u00020\tH'¢\u0006\u0004\b2\u0010 J\u001f\u00103\u001a\b\u0012\u0004\u0012\u0002000\u00022\b\b\u0001\u0010/\u001a\u00020\tH'¢\u0006\u0004\b3\u0010\rJ\u001f\u00104\u001a\b\u0012\u0004\u0012\u00020\u00010\u00022\b\b\u0001\u0010/\u001a\u00020\tH'¢\u0006\u0004\b4\u0010\rJ?\u00106\u001a\b\u0012\u0004\u0012\u0002000\u00022\b\b\u0001\u0010.\u001a\u00020\t2\b\b\u0001\u00105\u001a\u00020\t2\b\b\u0001\u0010\n\u001a\u00020\t2\n\b\u0001\u0010/\u001a\u0004\u0018\u00010\tH'¢\u0006\u0004\b6\u00107J\u0015\u00109\u001a\b\u0012\u0004\u0012\u0002080\u0002H'¢\u0006\u0004\b9\u0010\u0005J\u0015\u0010:\u001a\b\u0012\u0004\u0012\u00020\t0\u0002H'¢\u0006\u0004\b:\u0010\u0005J)\u0010>\u001a\b\u0012\u0004\u0012\u00020=0\u00022\b\b\u0001\u0010;\u001a\u00020\t2\b\b\u0001\u0010<\u001a\u00020\tH'¢\u0006\u0004\b>\u0010 J%\u0010@\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020?0\u00060\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u0010H'¢\u0006\u0004\b@\u0010#J\u001f\u0010A\u001a\b\u0012\u0004\u0012\u00020\t0\u00022\b\b\u0001\u0010/\u001a\u00020\tH'¢\u0006\u0004\bA\u0010\rJ%\u0010B\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020*0\u00060\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u0010H'¢\u0006\u0004\bB\u0010#J%\u0010D\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020C0\u00060\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u0010H'¢\u0006\u0004\bD\u0010#J%\u0010E\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020C0\u00060\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u0010H'¢\u0006\u0004\bE\u0010#JA\u0010I\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020C0\u00060\u00022$\b\u0001\u0010H\u001a\u001e\u0012\u0004\u0012\u00020\t\u0012\u0004\u0012\u00020\t0Fj\u000e\u0012\u0004\u0012\u00020\t\u0012\u0004\u0012\u00020\t`GH'¢\u0006\u0004\bI\u0010JJA\u0010K\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020C0\u00060\u00022$\b\u0001\u0010H\u001a\u001e\u0012\u0004\u0012\u00020\t\u0012\u0004\u0012\u00020\t0Fj\u000e\u0012\u0004\u0012\u00020\t\u0012\u0004\u0012\u00020\t`GH'¢\u0006\u0004\bK\u0010JJ%\u0010L\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020*0\u00060\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u0010H'¢\u0006\u0004\bL\u0010#J%\u0010N\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020M0\u00060\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u0010H'¢\u0006\u0004\bN\u0010#J%\u0010O\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020M0\u00060\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u0010H'¢\u0006\u0004\bO\u0010#J\u001f\u0010R\u001a\b\u0012\u0004\u0012\u00020Q0\u00022\b\b\u0001\u0010P\u001a\u00020\tH'¢\u0006\u0004\bR\u0010\rJ%\u0010T\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020S0\u00060\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u0010H'¢\u0006\u0004\bT\u0010#J%\u0010V\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020U0\u00060\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u0010H'¢\u0006\u0004\bV\u0010#¨\u0006W"}, m5311d2 = {"Lb/a/a/a/r/e;", "", "Lc/a/b2/b;", "Lcom/jbzd/media/movecartoons/bean/response/UserInfoBean;", "C", "()Lc/a/b2/b;", "", "Lcom/jbzd/media/movecartoons/bean/response/HeadImageBean$HeadImagesBean;", "g", "", "type", "Lcom/jbzd/media/movecartoons/bean/response/RechargeBean;", "q", "(Ljava/lang/String;)Lc/a/b2/b;", "Lcom/jbzd/media/movecartoons/bean/response/ShareInfoBean;", "o", "", "page", "chatId", "tradeId", "Lcom/jbzd/media/movecartoons/bean/response/ChatMsgBean;", "I", "(ILjava/lang/String;Ljava/lang/String;)Lc/a/b2/b;", "Lcom/jbzd/media/movecartoons/bean/request/ChatRequest;", "request", "f", "(Lcom/jbzd/media/movecartoons/bean/request/ChatRequest;)Lc/a/b2/b;", "Lcom/jbzd/media/movecartoons/bean/response/PicVefBean;", "F", "field", "name", C2743m.f7506a, "(Ljava/lang/String;Ljava/lang/String;)Lc/a/b2/b;", "Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsItemBean;", "z", "(I)Lc/a/b2/b;", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelItemsBean;", "w", "i", "v", "x", "u", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "B", "id", "b", "phone", "code", "Lcom/jbzd/media/movecartoons/bean/TokenBean;", "a", "n", "k", "h", "password", "K", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lc/a/b2/b;", "Lcom/jbzd/media/movecartoons/bean/response/VipInfoBean;", "c", ExifInterface.GPS_MEASUREMENT_IN_PROGRESS, "groupId", "paymentId", "Lcom/jbzd/media/movecartoons/bean/response/PayBean;", "t", "Lcom/jbzd/media/movecartoons/bean/response/ExchangeLogBean;", "j", C1568e.f1949a, "r", "Lcom/jbzd/media/movecartoons/bean/response/PostListBean;", "H", "s", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "body", ExifInterface.LONGITUDE_EAST, "(Ljava/util/HashMap;)Lc/a/b2/b;", "G", "l", "Lcom/jbzd/media/movecartoons/bean/response/FollowItem;", "D", "y", "userId", "Lcom/jbzd/media/movecartoons/bean/response/UserFollowResponse;", "J", "Lcom/jbzd/media/movecartoons/bean/response/IncomeLogBean;", "d", "Lcom/jbzd/media/movecartoons/bean/response/ShareBean;", "p", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* renamed from: b.a.a.a.r.e */
/* loaded from: classes2.dex */
public interface InterfaceC0921e {
    @InterfaceC5000o("user/vip")
    @NotNull
    /* renamed from: A */
    InterfaceC3006b<String> m231A();

    @InterfaceC4990e
    @InterfaceC5000o("movie/favorite")
    @NotNull
    /* renamed from: B */
    InterfaceC3006b<List<VideoItemBean>> m232B(@InterfaceC4988c("page") int page);

    @InterfaceC5000o("user/info")
    @NotNull
    /* renamed from: C */
    InterfaceC3006b<UserInfoBean> m233C();

    @InterfaceC4990e
    @InterfaceC5000o("user/fans")
    @NotNull
    /* renamed from: D */
    InterfaceC3006b<List<FollowItem>> m234D(@InterfaceC4988c("page") int page);

    @InterfaceC5000o("post/search")
    @NotNull
    /* renamed from: E */
    InterfaceC3006b<List<PostListBean>> m235E(@InterfaceC4986a @NotNull HashMap<String, String> body);

    @InterfaceC5000o("system/captcha")
    @NotNull
    /* renamed from: F */
    InterfaceC3006b<PicVefBean> m236F();

    @InterfaceC5000o("post/favorite")
    @NotNull
    /* renamed from: G */
    InterfaceC3006b<List<PostListBean>> m237G(@InterfaceC4986a @NotNull HashMap<String, String> body);

    @InterfaceC4990e
    @InterfaceC5000o("post/buyLogs")
    @NotNull
    /* renamed from: H */
    InterfaceC3006b<List<PostListBean>> m238H(@InterfaceC4988c("page") int page);

    @InterfaceC4990e
    @InterfaceC5000o("user/chatMessages")
    @NotNull
    /* renamed from: I */
    InterfaceC3006b<ChatMsgBean> m239I(@InterfaceC4988c("page") int page, @InterfaceC4988c("to_user_id") @Nullable String chatId, @InterfaceC4988c("trade_id") @Nullable String tradeId);

    @InterfaceC4990e
    @InterfaceC5000o("user/doFollow")
    @NotNull
    /* renamed from: J */
    InterfaceC3006b<UserFollowResponse> m240J(@InterfaceC4988c("id") @NotNull String userId);

    @InterfaceC4990e
    @InterfaceC5000o("user/findByAccount")
    @NotNull
    /* renamed from: K */
    InterfaceC3006b<TokenBean> m241K(@InterfaceC4988c("account_name") @NotNull String phone, @InterfaceC4988c("account_password") @NotNull String password, @InterfaceC4988c("type") @NotNull String type, @InterfaceC4988c("code") @Nullable String code);

    @InterfaceC4990e
    @InterfaceC5000o("user/findByPhone")
    @NotNull
    /* renamed from: a */
    InterfaceC3006b<TokenBean> m242a(@InterfaceC4988c("phone") @NotNull String phone, @InterfaceC4988c("code") @NotNull String code);

    @InterfaceC4990e
    @InterfaceC5000o("movie/delFavorite")
    @NotNull
    /* renamed from: b */
    InterfaceC3006b<Object> m243b(@InterfaceC4988c("ids") @NotNull String id);

    @InterfaceC5000o("user/vip")
    @NotNull
    /* renamed from: c */
    InterfaceC3006b<VipInfoBean> m244c();

    @InterfaceC4990e
    @InterfaceC5000o("user/incomeLog")
    @NotNull
    /* renamed from: d */
    InterfaceC3006b<List<IncomeLogBean>> m245d(@InterfaceC4988c("page") int page);

    @InterfaceC4990e
    @InterfaceC5000o("user/doCode")
    @NotNull
    /* renamed from: e */
    InterfaceC3006b<String> m246e(@InterfaceC4988c("code") @NotNull String code);

    @InterfaceC5000o("user/sendMessage")
    @NotNull
    /* renamed from: f */
    InterfaceC3006b<Object> m247f(@InterfaceC4986a @NotNull ChatRequest request);

    @InterfaceC5000o("user/images")
    @NotNull
    /* renamed from: g */
    InterfaceC3006b<List<HeadImageBean.HeadImagesBean>> m248g();

    @InterfaceC4990e
    @InterfaceC5000o("user/bindParent")
    @NotNull
    /* renamed from: h */
    InterfaceC3006b<Object> m249h(@InterfaceC4988c("code") @NotNull String code);

    @InterfaceC4990e
    @InterfaceC5000o("comics/history")
    @NotNull
    /* renamed from: i */
    InterfaceC3006b<List<ComicsItemBean>> m250i(@InterfaceC4988c("page") int page);

    @InterfaceC4990e
    @InterfaceC5000o("user/codeLogs")
    @NotNull
    /* renamed from: j */
    InterfaceC3006b<List<ExchangeLogBean>> m251j(@InterfaceC4988c("page") int page);

    @InterfaceC4990e
    @InterfaceC5000o("user/findQrcode")
    @NotNull
    /* renamed from: k */
    InterfaceC3006b<TokenBean> m252k(@InterfaceC4988c("code") @NotNull String code);

    @InterfaceC4990e
    @InterfaceC5000o("movie/history")
    @NotNull
    /* renamed from: l */
    InterfaceC3006b<List<VideoItemBean>> m253l(@InterfaceC4988c("page") int page);

    @InterfaceC4990e
    @InterfaceC5000o("user/updateInfo")
    @NotNull
    /* renamed from: m */
    InterfaceC3006b<Object> m254m(@InterfaceC4988c("field") @NotNull String field, @InterfaceC4988c("value") @NotNull String name);

    @InterfaceC4990e
    @InterfaceC5000o("user/bindPhone")
    @NotNull
    /* renamed from: n */
    InterfaceC3006b<TokenBean> m255n(@InterfaceC4988c("phone") @NotNull String phone, @InterfaceC4988c("code") @NotNull String code);

    @InterfaceC5000o("user/shareInfo")
    @NotNull
    /* renamed from: o */
    InterfaceC3006b<ShareInfoBean> m256o();

    @InterfaceC4990e
    @InterfaceC5000o("user/shareLogs")
    @NotNull
    /* renamed from: p */
    InterfaceC3006b<List<ShareBean>> m257p(@InterfaceC4988c("page") int page);

    @InterfaceC4990e
    @InterfaceC5000o("user/recharge")
    @NotNull
    /* renamed from: q */
    InterfaceC3006b<RechargeBean> m258q(@InterfaceC4988c("type") @NotNull String type);

    @InterfaceC4990e
    @InterfaceC5000o("movie/buyLogs")
    @NotNull
    /* renamed from: r */
    InterfaceC3006b<List<VideoItemBean>> m259r(@InterfaceC4988c("page") int page);

    @InterfaceC4990e
    @InterfaceC5000o("post/myAi")
    @NotNull
    /* renamed from: s */
    InterfaceC3006b<List<PostListBean>> m260s(@InterfaceC4988c("page") int page);

    @InterfaceC4990e
    @InterfaceC5000o("user/doVip")
    @NotNull
    /* renamed from: t */
    InterfaceC3006b<PayBean> m261t(@InterfaceC4988c("group_id") @NotNull String groupId, @InterfaceC4988c("payment_id") @NotNull String paymentId);

    @InterfaceC4990e
    @InterfaceC5000o("comics/buyLogs")
    @NotNull
    /* renamed from: u */
    InterfaceC3006b<List<ComicsItemBean>> m262u(@InterfaceC4988c("page") int page);

    @InterfaceC4990e
    @InterfaceC5000o("novel/history")
    @NotNull
    /* renamed from: v */
    InterfaceC3006b<List<NovelItemsBean>> m263v(@InterfaceC4988c("page") int page);

    @InterfaceC4990e
    @InterfaceC5000o("novel/favorite")
    @NotNull
    /* renamed from: w */
    InterfaceC3006b<List<NovelItemsBean>> m264w(@InterfaceC4988c("page") int page);

    @InterfaceC4990e
    @InterfaceC5000o("novel/buyLogs")
    @NotNull
    /* renamed from: x */
    InterfaceC3006b<List<NovelItemsBean>> m265x(@InterfaceC4988c("page") int page);

    @InterfaceC4990e
    @InterfaceC5000o("user/follow")
    @NotNull
    /* renamed from: y */
    InterfaceC3006b<List<FollowItem>> m266y(@InterfaceC4988c("page") int page);

    @InterfaceC4990e
    @InterfaceC5000o("comics/favorite")
    @NotNull
    /* renamed from: z */
    InterfaceC3006b<List<ComicsItemBean>> m267z(@InterfaceC4988c("page") int page);
}
