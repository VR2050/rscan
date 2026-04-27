package com.bjz.comm.net.mvp.model;

import com.android.tools.r8.annotations.SynthesizedClassMap;
import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.RespFcListBean;
import com.bjz.comm.net.factory.ApiFactory;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.utils.RxHelper;
import io.reactivex.Observable;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes4.dex */
@SynthesizedClassMap({$$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI.class, $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s.class})
public class FcPageRecommendModel implements BaseFcContract.IFcPageRecommendModel {
    private static final String TAG = FcPageRecommendModel.class.getSimpleName();

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageRecommendModel
    public void getFcList(int limit, long forumID, DataListener<BResponse<ArrayList<RespFcListBean>>> listener) {
        Observable<BResponse<ArrayList<RespFcListBean>>> observable = ApiFactory.getInstance().getApiMomentForum().getHomePageRecommendList(limit, forumID);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s __lambda_msgpat9jjinhbatbtfcu4d9tp7s = new $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s(listener);
        listener.getClass();
        rxHelper.sendRequest(str, observable, __lambda_msgpat9jjinhbatbtfcu4d9tp7s, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.base.IBModel
    public void unSubscribeTask() {
        RxHelper.getInstance().lambda$sendSimpleRequest$0$RxHelper(TAG);
    }
}
