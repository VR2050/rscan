package com.jbzd.media.movecartoons.p396ui.wallet;

import com.jbzd.media.movecartoons.bean.response.GroupBean;
import com.jbzd.media.movecartoons.bean.response.PayBean;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0004\bf\u0018\u00002\u00020\u0001JB\u0010\r\u001a\u00020\u000b2\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042!\u0010\f\u001a\u001d\u0012\u0013\u0012\u00110\u0007¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0004\u0012\u00020\u000b0\u0006H&¢\u0006\u0004\b\r\u0010\u000e¨\u0006\u000f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/wallet/IdoPay;", "", "Lcom/jbzd/media/movecartoons/bean/response/GroupBean$PaymentsBean;", "payment", "Lcom/jbzd/media/movecartoons/bean/response/GroupBean;", "vipGroup", "Lkotlin/Function1;", "Lcom/jbzd/media/movecartoons/bean/response/PayBean;", "Lkotlin/ParameterName;", "name", "paybean", "", "onSuccess", "doPay", "(Lcom/jbzd/media/movecartoons/bean/response/GroupBean$PaymentsBean;Lcom/jbzd/media/movecartoons/bean/response/GroupBean;Lkotlin/jvm/functions/Function1;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public interface IdoPay {
    void doPay(@NotNull GroupBean.PaymentsBean payment, @NotNull GroupBean vipGroup, @NotNull Function1<? super PayBean, Unit> onSuccess);
}
