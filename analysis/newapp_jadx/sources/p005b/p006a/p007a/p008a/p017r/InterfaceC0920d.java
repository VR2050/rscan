package p005b.p006a.p007a.p008a.p017r;

import com.jbzd.media.movecartoons.bean.UploadPicResponse;
import com.jbzd.media.movecartoons.bean.UploadVideoResponse;
import com.jbzd.media.movecartoons.bean.response.UploadVideoResultResponse;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;
import p379c.p380a.InterfaceC3067i0;
import p458k.AbstractC4387j0;
import p458k.AbstractC4393m0;
import p505n.p506e0.InterfaceC4986a;
import p505n.p506e0.InterfaceC5000o;
import p505n.p506e0.InterfaceC5005t;
import p505n.p506e0.InterfaceC5010y;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\bf\u0018\u00002\u00020\u0001J)\u0010\b\u001a\b\u0012\u0004\u0012\u00020\u00070\u00062\b\b\u0001\u0010\u0003\u001a\u00020\u00022\b\b\u0001\u0010\u0005\u001a\u00020\u0004H'¢\u0006\u0004\b\b\u0010\tJe\u0010\u0014\u001a\b\u0012\u0004\u0012\u00020\u00130\u00062\b\b\u0001\u0010\u000b\u001a\u00020\n2\b\b\u0001\u0010\f\u001a\u00020\u00022\b\b\u0001\u0010\r\u001a\u00020\n2\b\b\u0001\u0010\u000e\u001a\u00020\u00022\b\b\u0001\u0010\u000f\u001a\u00020\u00022\b\b\u0001\u0010\u0010\u001a\u00020\u00022\b\b\u0001\u0010\u0011\u001a\u00020\u00022\b\b\u0001\u0010\u0012\u001a\u00020\u0004H'¢\u0006\u0004\b\u0014\u0010\u0015J)\u0010\u0018\u001a\b\u0012\u0004\u0012\u00020\u00170\u00062\b\b\u0001\u0010\u000e\u001a\u00020\u00022\b\b\u0001\u0010\u0016\u001a\u00020\u0002H'¢\u0006\u0004\b\u0018\u0010\u0019JQ\u0010\u001d\u001a\b\u0012\u0004\u0012\u00020\u001c0\u00062\b\b\u0001\u0010\u000e\u001a\u00020\u00022\b\b\u0001\u0010\u000f\u001a\u00020\u00022\b\b\u0001\u0010\u0010\u001a\u00020\u00022\b\b\u0001\u0010\u001a\u001a\u00020\u00022\b\b\u0001\u0010\u001b\u001a\u00020\u00022\b\b\u0001\u0010\u0012\u001a\u00020\u0004H'¢\u0006\u0004\b\u001d\u0010\u001e¨\u0006\u001f"}, m5311d2 = {"Lb/a/a/a/r/d;", "", "", "url", "Lk/j0;", "parameterStream", "Lc/a/i0;", "Lk/m0;", "d", "(Ljava/lang/String;Lk/j0;)Lc/a/i0;", "", "page", "md5", "total_page", "key", "user_id", "file_name", "preview", "body", "Lcom/jbzd/media/movecartoons/bean/response/UploadVideoResultResponse;", "a", "(ILjava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lk/j0;)Lc/a/i0;", "id", "Lcom/jbzd/media/movecartoons/bean/UploadVideoResponse;", "b", "(Ljava/lang/String;Ljava/lang/String;)Lc/a/i0;", "small", "compress", "Lcom/jbzd/media/movecartoons/bean/UploadPicResponse;", "c", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lk/j0;)Lc/a/i0;", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* renamed from: b.a.a.a.r.d */
/* loaded from: classes2.dex */
public interface InterfaceC0920d {
    @InterfaceC5000o("byte")
    @NotNull
    /* renamed from: a */
    InterfaceC3067i0<UploadVideoResultResponse> m227a(@InterfaceC5005t("page") int page, @InterfaceC5005t("md5") @NotNull String md5, @InterfaceC5005t("total_page") int total_page, @InterfaceC5005t("key") @NotNull String key, @InterfaceC5005t("user_id") @NotNull String user_id, @InterfaceC5005t("file_name") @NotNull String file_name, @InterfaceC5005t("preview") @NotNull String preview, @InterfaceC4986a @NotNull AbstractC4387j0 body);

    @InterfaceC5000o("query")
    @NotNull
    /* renamed from: b */
    InterfaceC3067i0<UploadVideoResponse> m228b(@InterfaceC5005t("key") @NotNull String key, @InterfaceC5005t("id") @NotNull String id);

    @InterfaceC5000o("image")
    @NotNull
    /* renamed from: c */
    InterfaceC3067i0<UploadPicResponse> m229c(@InterfaceC5005t("key") @NotNull String key, @InterfaceC5005t("user_id") @NotNull String user_id, @InterfaceC5005t("file_name") @NotNull String file_name, @InterfaceC5005t("small") @NotNull String small, @InterfaceC5005t("compress") @NotNull String compress, @InterfaceC4986a @NotNull AbstractC4387j0 body);

    @InterfaceC5000o
    @NotNull
    /* renamed from: d */
    InterfaceC3067i0<AbstractC4393m0> m230d(@InterfaceC5010y @NotNull String url, @InterfaceC4986a @NotNull AbstractC4387j0 parameterStream);
}
