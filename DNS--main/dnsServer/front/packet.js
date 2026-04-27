class PacketPager {
    /**
     * @param {Object} opts
     *   - containerId: 容器元素ID
     *   - pageSize: 每页数量
     *   - fetchData: 拉取数据函数，返回Promise<array>
     *   - onDetail: 查看详情回调 (id)
     *   - onDelete: 批量删除回调 (ids, doneCallback)
     *   - renderExtra: 额外渲染内容函数 (item) => html
     *   - emptyMsg: 无数据时显示
     */
    constructor(opts) {
        this.containerId = opts.containerId;
        this.pageSize = opts.pageSize || 10;
        this.fetchData = opts.fetchData;
        this.onDetail = opts.onDetail;
        this.onDelete = opts.onDelete;
        this.renderExtra = opts.renderExtra;
        this.emptyMsg = opts.emptyMsg || "无包";
        this.allData = [];
        this.selectedIds = new Set();
        this.page = 1;
        this.totalPages = 1;
        this.pageInputId = `gotoPageInput_${this.containerId}`;
        this._bindWindowEvents();
    }

    _bindWindowEvents() {
        // 绑定到window，避免多实例冲突
        window[`_selectAllPacketsThisPage_${this.containerId}`] = (checked) => this.selectAllThisPage(checked);
        window[`_onPacketCheckboxChange_${this.containerId}`] = (id, checked) => this.onCheckboxChange(id, checked);
        window[`_changePacketPage_${this.containerId}`] = (delta) => this.changePage(delta);
        window[`_gotoPacketPage_${this.containerId}`] = () => this.gotoPage();
        window[`_onPacketDetail_${this.containerId}`] = (id) => this.onDetail(id);
        window[`_onPacketDelete_${this.containerId}`] = () => this.deleteSelected();
    }

    load() {
        this.fetchData().then(list => {
            this.allData = list || [];
            this.selectedIds.clear();
            this.page = 1;
            this.totalPages = Math.max(1, Math.ceil(this.allData.length / this.pageSize));
            this.render();
        });
    }

    render() {
    const el = document.getElementById(this.containerId);
    if (!el) return;

    if (!this.allData.length) {
        el.innerHTML = this.emptyMsg;
        return;
    }

    const start = (this.page - 1) * this.pageSize;
    const end = start + this.pageSize;
    const pageData = this.allData.slice(start, end);

    el.innerHTML = `
        <div style="margin-bottom: 16px; text-align: right;">
            <button onclick="window._selectAllPacketsThisPage_${this.containerId}(true)">全选该页</button>
            <button onclick="window._selectAllPacketsThisPage_${this.containerId}(false)" style="margin-left:10px;">取消全选</button>
            <button onclick="window._onPacketDelete_${this.containerId}()" style="color:#f44336; margin-left:10px;">批量删除</button>
        </div>

        <div class="packet-list-grid">
            ${pageData.map((f) => `
                <div class="packet-card">
                    <div style="display:flex; align-items:center; margin-bottom:8px;">
                        <input type="checkbox" class="packet-checkbox-${this.containerId}" value="${f.id}"
                               ${this.selectedIds.has(f.id) ? "checked" : ""}
                               onchange="window._onPacketCheckboxChange_${this.containerId}(${f.id}, this.checked)">
                        <strong style="margin-left:8px;">时间:</strong> ${f.timestamp}
                    </div>
                    <div><strong>设备:</strong> ${f.device_id || "未知"}</div>
                    <div><strong>源 IP:</strong> ${f.src_ip}</div>
                    <div><strong>目标 IP:</strong> ${f.dst_ip}</div>
                    <div><strong>协议:</strong> ${f.protocol}</div>
                    <button onclick="window._onPacketDetail_${this.containerId}(${f.id})" style="margin-top: 8px;">查看详情</button>
                    ${this.renderExtra ? this.renderExtra(f) : ""}
                </div>
            `).join("")}
        </div>

        <div class="pagination-controls">
            <button onclick="window._changePacketPage_${this.containerId}(-1)" ${this.page === 1 ? "disabled" : ""}>上一页</button>
            <span>第 ${this.page} 页 / 共 ${this.totalPages} 页</span>
            <button onclick="window._changePacketPage_${this.containerId}(1)" ${end >= this.allData.length ? "disabled" : ""}>下一页</button>
        </div>

        <div class="pagination-jump">
            跳转到第 
            <input id="${this.pageInputId}" type="number" min="1" max="${this.totalPages}" value="${this.page}" style="width: 60px;" />
            页 <button onclick="window._gotoPacketPage_${this.containerId}()">跳转</button>
        </div>
    `;
}


    selectAllThisPage(checked) {
        const start = (this.page - 1) * this.pageSize;
        const end = start + this.pageSize;
        const pageData = this.allData.slice(start, end);
        pageData.forEach(f => {
            if (checked) this.selectedIds.add(f.id);
            else this.selectedIds.delete(f.id);
        });
        this.render();
    }

    onCheckboxChange(id, checked) {
        if (checked) this.selectedIds.add(id);
        else this.selectedIds.delete(id);
    }

    changePage(delta) {
        this.page += delta;
        if (this.page < 1) this.page = 1;
        if (this.page > this.totalPages) this.page = this.totalPages;
        this.render();
    }

    gotoPage() {
        const input = document.getElementById(this.pageInputId);
        const page = parseInt(input.value, 10);
        if (isNaN(page) || page < 1 || page > this.totalPages) {
            alert(`请输入有效页码（1 - ${this.totalPages}）`);
            return;
        }
        this.page = page;
        this.render();
    }

    deleteSelected() {
        const ids = Array.from(this.selectedIds);
        if (!ids.length) {
            alert("请先选择要删除的包");
            return;
        }
        if (!confirm(`确定要删除选中的${ids.length}个包吗？`)) return;
        this.onDelete(ids, () => {
            this.selectedIds.clear();
            this.load();
        });
    }
}

// 管理员包管理
const adminPacketPager = new PacketPager({
    containerId: "fileQueryResult",
    pageSize: 10,
    fetchData: function () {
        const deviceID = document.getElementById("queryDeviceID").value;
        const start = document.getElementById("queryStartTime").value;
        const end = document.getElementById("queryEndTime").value;
        let url = `/api/admin/packet/query?`;
        if (deviceID) url += `device_id=${encodeURIComponent(deviceID)}&`;
        if (start) url += `start=${encodeURIComponent(start)}&`;
        if (end) url += `end=${encodeURIComponent(end)}`;
        return authFetch(url).then(r => r.json());
    },
    onDetail: showPacketDetail,
    onDelete: function (ids, done) {
        authFetch("/api/admin/packet/delete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ids })
        }).then(async (res) => {
            if (res.ok) {
                alert("批量删除成功");
                done();
            } else {
                const msg = await res.text();
                alert("批量删除失败：" + (msg || "未知错误"));
            }
        }).catch((e) => {
            alert("请求失败：" + (e.message || "未知错误"));
        });
    }
});

// 用户包管理
const userPacketPager = new PacketPager({
    containerId: "userPacketList",
    pageSize: 10,
    fetchData: function () {
        return authFetch("/api/user/packet/query")
            .then(r => {
                if (!r.ok) {
                    return r.text().then(t => { throw new Error(t || "请求失败"); });
                }
                return r.json();
            });
    },
    onDetail: showPacketDetail,
    onDelete: function (ids, done) {
        authFetch("/api/user/packet/delete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ids })
        })
            .then(async (res) => {
                if (res.ok) {
                    done();
                } else {
                    const msg = await res.text();
                    alert("批量删除失败：" + (msg || "未知错误"));
                }
            })
            .catch((e) => {
                alert("请求失败：" + (e.message || "未知错误"));
            });
    }
});

// 管理员查询捕获包
function adminFetchPacket() {
    adminPacketPager.load();
}

// 用户查询包
function userfetchPacket() {
    userPacketPager.load();
}

// 包详情
function showPacketDetail(id) {
    authFetch(`/api/packets/detail?id=${id}`)
        .then((r) => r.json())
        .then((res) => {
            showContent(res.dns_data);
        })
        .catch(() => alert("获取包详情失败"));
}

// 合并后的显示包详情弹窗函数
function showContent(jsonContent, dlgId = "packetDetail") {
    let dlg = document.getElementById(dlgId);

    if (!dlg) {
        dlg = document.createElement("div");
        dlg.id = dlgId;
        dlg.className = "modal";
        dlg.style.cssText = `
            display: flex;
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.5);
            justify-content: center;
            align-items: center;
            z-index: 9999;
        `;
        dlg.innerHTML = `
            <div class="modal-content" style="
                background: white;
                border-radius: 8px;
                max-width: 800px;
                width: 90%;
                padding: 20px;
                font-family: sans-serif;
                box-shadow: 0 4px 10px rgba(0, 0, 0, 0.2);
                overflow-y: auto;
                max-height: 90vh;
            "></div>`;
        document.body.appendChild(dlg);
    }

    dlg.style.display = "flex";

    let parsed;
    try {
        parsed = typeof jsonContent === "string" ? JSON.parse(jsonContent) : jsonContent;
    } catch {
        dlg.querySelector(".modal-content").innerHTML = `<pre>${jsonContent}</pre>`;
        return;
    }

    const { dns, network, metadata } = parsed;

    const formatAnswers = (answers = []) => {
        if (!answers.length) return "<p>无应答记录</p>";
        return `
            <table style="width:100%; border-collapse: collapse; margin-top: 8px;">
                <thead>
                    <tr style="background: #f0f0f0;">
                        <th style="padding: 6px; border: 1px solid #ddd;">Name</th>
                        <th style="padding: 6px; border: 1px solid #ddd;">Type</th>
                        <th style="padding: 6px; border: 1px solid #ddd;">Class</th>
                        <th style="padding: 6px; border: 1px solid #ddd;">Address</th>
                        <th style="padding: 6px; border: 1px solid #ddd;">TTL</th>
                    </tr>
                </thead>
                <tbody>
                    ${answers.map(ans => `
                        <tr>
                            <td style="padding: 6px; border: 1px solid #eee;">${ans.name}</td>
                            <td style="padding: 6px; border: 1px solid #eee;">${ans.type}</td>
                            <td style="padding: 6px; border: 1px solid #eee;">${ans.class}</td>
                            <td style="padding: 6px; border: 1px solid #eee;">${ans.address}</td>
                            <td style="padding: 6px; border: 1px solid #eee;">${ans.ttl}</td>
                        </tr>
                    `).join("")}
                </tbody>
            </table>`;
    };

    dlg.querySelector(".modal-content").innerHTML = `
        <div style="text-align: right;">
            <button class="modal-close-btn" style="
                background: #ff5c5c;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 14px;
            " onclick="document.body.removeChild(document.getElementById('${dlgId}'))">关闭</button>
        </div>

        <div style="margin-top: 12px;">
            <div style="margin-bottom: 20px;">
                <h3 style="margin-bottom: 8px;">🧩 DNS 信息</h3>
                <div><b>Transaction ID:</b> ${dns?.transaction_id || "N/A"}</div>
                <div><b>Opcode:</b> ${dns?.opcode || "N/A"}</div>
                <div><b>RCode:</b> ${dns?.rcode || "N/A"}</div>
                ${formatAnswers(dns?.answers)}
            </div>

            <div style="margin-bottom: 20px;">
                <h3 style="margin-bottom: 8px;">🌐 网络信息</h3>
                <ul style="list-style: none; padding-left: 0;">
                    <li><b>源 IP:</b> ${network?.src_ip || "N/A"}</li>
                    <li><b>源端口:</b> ${network?.src_port || "N/A"}</li>
                    <li><b>目标 IP:</b> ${network?.dst_ip || "N/A"}</li>
                    <li><b>目标端口:</b> ${network?.dst_port || "N/A"}</li>
                    <li><b>协议:</b> ${network?.protocol || "N/A"}</li>
                </ul>
            </div>

            <div>
                <h3 style="margin-bottom: 8px;">🗂️ 元信息</h3>
                <ul style="list-style: none; padding-left: 0;">
                    <li><b>设备 ID:</b> ${metadata?.device_id || "N/A"}</li>
                    <li><b>采集器版本:</b> ${metadata?.collector_version || "N/A"}</li>
                    <li><b>时间戳:</b> ${metadata?.timestamp || "N/A"}</li>
                </ul>
            </div>
        </div>
    `;
}