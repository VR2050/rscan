package M;

import java.lang.reflect.InvocationHandler;
import org.chromium.support_lib_boundary.WebMessageBoundaryInterface;

/* JADX INFO: loaded from: classes.dex */
public abstract class d implements WebMessageBoundaryInterface {
    private static L.c[] a(InvocationHandler[] invocationHandlerArr) {
        L.c[] cVarArr = new L.c[invocationHandlerArr.length];
        for (int i3 = 0; i3 < invocationHandlerArr.length; i3++) {
            cVarArr[i3] = new f(invocationHandlerArr[i3]);
        }
        return cVarArr;
    }

    public static L.b b(WebMessageBoundaryInterface webMessageBoundaryInterface) {
        return new L.b(webMessageBoundaryInterface.getData(), a(webMessageBoundaryInterface.getPorts()));
    }
}
