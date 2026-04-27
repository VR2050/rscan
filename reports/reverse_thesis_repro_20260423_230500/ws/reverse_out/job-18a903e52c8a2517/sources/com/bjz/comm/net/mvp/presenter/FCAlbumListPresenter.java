package com.bjz.comm.net.mvp.presenter;

import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.RespFcAlbumListBean;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.mvp.model.FCPageAlbumListModel;
import com.bjz.comm.net.utils.RxHelper;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes4.dex */
public class FCAlbumListPresenter implements BaseFcContract.IFcPageAlbumListPresenter {
    private BaseFcContract.IFcPageAlbumListView mView;
    private FCPageAlbumListModel model;

    public FCAlbumListPresenter(BaseFcContract.IFcPageAlbumListView view) {
        this.model = null;
        this.mView = view;
        if (0 == 0) {
            this.model = new FCPageAlbumListModel();
        }
    }

    @Override // com.bjz.comm.net.base.IBPresenter
    public void unSubscribeTask() {
        this.model.unSubscribeTask();
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcPageAlbumListPresenter
    public void getAlbumList(int userId, long id, int limit) {
        this.model.getAlbumList(userId, id, limit, new DataListener<BResponse<ArrayList<RespFcAlbumListBean>>>() { // from class: com.bjz.comm.net.mvp.presenter.FCAlbumListPresenter.1
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<ArrayList<RespFcAlbumListBean>> result) {
                if (result == null) {
                    FCAlbumListPresenter.this.mView.getAlbumListFailed(null);
                } else if (result.isState()) {
                    FCAlbumListPresenter.this.mView.getAlbumListSucc(result.Data == null ? new ArrayList<>() : result.Data);
                } else {
                    FCAlbumListPresenter.this.mView.getAlbumListFailed(result.Message);
                }
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FCAlbumListPresenter.this.mView.getAlbumListFailed(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }
}
