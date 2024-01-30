package agent

// func TestAgent_DoCommand(t *testing.T) {
// 	handlerAuth := func(w http.ResponseWriter, r *http.Request) {
// 		if _, err := w.Write([]byte(`{"token": "token", "key": "server key"}`)); err != nil {
// 			t.Errorf("write response error in auth: %v", err)
// 		}
// 	}
// 	sa := httptest.NewServer(http.HandlerFunc(handlerAuth))
// 	ca := config.Config{Login: "admin", Pwd: "pwd", Key: "key", Path: path.Join(t.TempDir(), "cfg.tmp")}
// 	strg, err := storage.NewNetStorage("", "key")
// 	strg.StorageCashe = &storage.Cashe{FilePath: path.Join(t.TempDir(), ".cashe"), Key: "cashe key"}
// 	if !errors.Is(err, storage.ErrConnection) {
// 		t.Errorf("create storage error: %v", err)
// 		return
// 	}
// 	agent := &Agent{RStorage: strg, Config: &ca}
// 	t.Run("Авторизация пользователя", func(t *testing.T) {
// 		ca.Command = "login"
// 		strg.ServerAddress = sa.URL
// 		if err := agent.DoCommand(); err != nil {
// 			t.Errorf("auth error: %v", err)
// 			return
// 		}
// 		if ca.Token != "token" {
// 			t.Errorf("unexpected token: %s", ca.Token)
// 			return
// 		}
// 	})
// 	strg.ServerAddress = "https://127.0.0.1:0"
// 	t.Run("Значение из кеша", func(t *testing.T) {
// 		ca.Command = storage.DatasType
// 		err := strg.StorageCashe.SetValue(ca.Command, "", "value")
// 		if err != nil {
// 			t.Errorf("cashe value error: %v", err)
// 			return
// 		}
// 		ca.ServerAddres = ""
// 		err = agent.DoCommand()
// 		if err != nil {
// 			t.Errorf("unexpected error: %v", err)
// 			return
// 		}
// 	})
// 	t.Run("Ошибка подключения", func(t *testing.T) {
// 		ca.Command = storage.CardsType
// 		err := agent.DoCommand()
// 		if err == nil {
// 			t.Error("error is nil")
// 			return
// 		}
// 		if !errors.Is(err, storage.ErrConnection) {
// 			t.Errorf("unexpected error: %v", err)
// 			return
// 		}
// 		if !errors.Is(err, storage.ErrConnection) {
// 			t.Errorf("unexpected cashe error: %v", err)
// 			return
// 		}
// 	})
// 	t.Run("Ошибка сохранения кеша", func(t *testing.T) {
// 		h := func(w http.ResponseWriter, r *http.Request) {
// 			l := make([]storage.DataInfo, 0)
// 			l = append(l, storage.DataInfo{Label: "card", Info: "info"})
// 			data, err := json.Marshal(&l)
// 			if err != nil {
// 				t.Errorf("marshal test data error: %v", err)
// 				w.WriteHeader(http.StatusInternalServerError)
// 				return
// 			}
// 			if _, err := w.Write(data); err != nil {
// 				t.Errorf("write response error: %v", err)
// 			}
// 		}
// 		serv := httptest.NewServer(http.HandlerFunc(h))
// 		ca.Command = storage.CardsType
// 		strg.ServerAddress = serv.URL
// 		err := agent.DoCommand()
// 		if err != nil {
// 			t.Errorf("unexpected error: %v", err)
// 			return
// 		}
// 		p := strg.StorageCashe.FilePath
// 		strg.StorageCashe.FilePath = t.TempDir()
// 		defer func() {
// 			strg.StorageCashe.FilePath = p
// 		}()
// 		if err := agent.DoCommand(); err == nil {
// 			t.Error("set cashe value error is nil")
// 		}
// 	})
// 	t.Run("Удаление", func(t *testing.T) {
// 		success, notFound := "1", "2"
// 		h := func(w http.ResponseWriter, r *http.Request) {
// 			s := strings.Split(r.URL.Path, "/")
// 			id := ""
// 			for _, v := range s {
// 				id = v
// 			}
// 			switch id {
// 			case success:
// 				w.WriteHeader(http.StatusOK)
// 			case notFound:
// 				w.WriteHeader(http.StatusNotFound)
// 			default:
// 				w.WriteHeader(http.StatusBadGateway)
// 			}
// 		}
// 		serv := httptest.NewServer(http.HandlerFunc(h))
// 		ca.Command = "cards_del"
// 		ca.Arg = success
// 		strg.ServerAddress = serv.URL
// 		if err := agent.DoCommand(); err != nil {
// 			t.Errorf("unexpected error: %v, want: nil", err)
// 			return
// 		}
// 		ca.Arg = notFound
// 		if err := agent.DoCommand(); !errors.Is(err, storage.ErrNotFound) {
// 			t.Errorf("unexpected error: %v, want: %v", err, storage.ErrNotFound)
// 			return
// 		}
// 		ca.Arg = "3"
// 		if err := agent.DoCommand(); !errors.Is(err, storage.ErrStatusCode) {
// 			t.Errorf("unexpected error: %v, want: %v", err, storage.ErrStatusCode)
// 			return
// 		}
// 	})
// 	t.Run("Локальное хранилище", func(t *testing.T) {
// 		ca.Command = "local"
// 		if err := agent.DoCommand(); err != nil {
// 			t.Errorf("unexpected error: %v", err)
// 		}
// 		ca.Command = "local_clear"
// 		if err := agent.DoCommand(); err != nil {
// 			t.Errorf("unexpected error: %v", err)
// 		}
// 		ca.Command = "local_sync"
// 		if err := agent.DoCommand(); err != nil {
// 			t.Errorf("unexpected error: %v", err)
// 		}
// 	})
// 	t.Run("Неизвестная команда", func(t *testing.T) {
// 		ca.Command = "undefined"
// 		ca.ServerAddres = sa.URL
// 		agent := &Agent{Config: &ca}
// 		err := agent.DoCommand()
// 		if !errors.Is(err, ErrUndefinedTarget) {
// 			t.Errorf("unexpected error: %v", err)
// 		}
// 	})
// }
