package p005b.p085c.p088b.p089a;

/* renamed from: b.c.b.a.g */
/* loaded from: classes.dex */
public enum EnumC1350g {
    SUCCEEDED(9000, "处理成功"),
    FAILED(4000, "系统繁忙，请稍后再试"),
    CANCELED(6001, "用户取消"),
    NETWORK_ERROR(6002, "网络连接异常"),
    PARAMS_ERROR(4001, "参数错误"),
    DOUBLE_REQUEST(5000, "重复请求"),
    PAY_WAITTING(8000, "支付结果确认中");


    /* renamed from: l */
    public int f1179l;

    /* renamed from: m */
    public String f1180m;

    EnumC1350g(int i2, String str) {
        this.f1179l = i2;
        this.f1180m = str;
    }

    /* renamed from: a */
    public static EnumC1350g m358a(int i2) {
        return i2 != 4001 ? i2 != 5000 ? i2 != 8000 ? i2 != 9000 ? i2 != 6001 ? i2 != 6002 ? FAILED : NETWORK_ERROR : CANCELED : SUCCEEDED : PAY_WAITTING : DOUBLE_REQUEST : PARAMS_ERROR;
    }
}
