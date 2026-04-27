package com.bjz.comm.net.mvp.model;

import com.android.tools.r8.annotations.SynthesizedClassMap;
import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.BResponseNoData;
import com.bjz.comm.net.bean.RespFcListBean;
import com.bjz.comm.net.bean.RespFcUserStatisticsBean;
import com.bjz.comm.net.factory.ApiFactory;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.utils.JsonCreateUtils;
import com.bjz.comm.net.utils.RxHelper;
import io.reactivex.Observable;
import java.util.ArrayList;
import okhttp3.RequestBody;

/* JADX INFO: loaded from: classes4.dex */
@SynthesizedClassMap({$$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI.class, $$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo.class, $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s.class})
public class FcPageMineModel implements BaseFcContract.IFcPageMineModel {
    private static final String TAG = FcPageMineModel.class.getSimpleName();

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageMineModel
    public void getFCList(int limit, long forumID, DataListener<BResponse<ArrayList<RespFcListBean>>> listener) {
        Observable<BResponse<ArrayList<RespFcListBean>>> observable = ApiFactory.getInstance().getApiMomentForum().getMyFCList(limit, forumID);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s __lambda_msgpat9jjinhbatbtfcu4d9tp7s = new $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s(listener);
        listener.getClass();
        rxHelper.sendRequest(str, observable, __lambda_msgpat9jjinhbatbtfcu4d9tp7s, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageMineModel
    public void getActionCount(long userId, DataListener<BResponse<RespFcUserStatisticsBean>> listener) {
        Observable<BResponse<RespFcUserStatisticsBean>> observable = ApiFactory.getInstance().getApiMomentForum().getActionCount(userId);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s __lambda_msgpat9jjinhbatbtfcu4d9tp7s = new $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s(listener);
        listener.getClass();
        rxHelper.sendRequest(str, observable, __lambda_msgpat9jjinhbatbtfcu4d9tp7s, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageMineModel
    public void setFcBackground(String homeBackground, DataListener<BResponseNoData> listener) {
        RequestBody requestBody = JsonCreateUtils.build().addParam("HomeBackground", homeBackground).getHttpBody();
        Observable<BResponseNoData> observable = ApiFactory.getInstance().getApiMomentForum().setFcBackground(requestBody);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo __lambda_q4eitxgqnlbs9f1srtgjxo_xkco = new $$Lambda$Q4eiTxgqNLBS9F1srtGjxo_XKCo(listener);
        listener.getClass();
        rxHelper.sendCommRequest(str, observable, __lambda_q4eitxgqnlbs9f1srtgjxo_xkco, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.base.IBModel
    public void unSubscribeTask() {
        RxHelper.getInstance().lambda$sendSimpleRequest$0$RxHelper(TAG);
    }
}
