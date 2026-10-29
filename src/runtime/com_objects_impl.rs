//! COM/device object construction glue (runtime methods).

use super::*;

impl PeHostRuntime {
    /// Try to create a guest COM object for a given CLSID string, returning
    /// `Some(object_address)` on success or `None` if the CLSID is not recognised.
    ///
    /// This is the shared code path used by both `CoCreateInstance` and
    /// `ComFactoryCreateInstance` — eliminates the duplicated hardcoded CLSID
    /// matching that existed previously.
    pub(crate) fn try_create_com_object(
        &mut self,
        memory: &mut MemoryImage,
        clsid: &str,
        iid: &str,
        _flags: u32,
    ) -> AppResult<Option<u64>> {
        // A registry-backed class runs through its live registration first:
        // the in-process class table carries the registered InprocServer32
        // path/threading model, so activation follows registration state.
        if let Some(object) = self.try_create_registered_com_class(memory, clsid)? {
            return Ok(Some(object));
        }
        // The runtime's in-process automation/event-source class: a real
        // IDispatch property/method server with an IConnectionPointContainer
        // for sink advice (the runtime's synthetic in-process class table).
        if clsid.eq_ignore_ascii_case(crate::runtime::dispatch::com::COM_AUTOMATION_SERVER_CLSID) {
            let server = self.alloc_com_automation_server(memory, "ICasa1Automation")?;
            return Ok(Some(server));
        }
        // Shell Link CLSID
        if clsid.eq_ignore_ascii_case(SHELL_LINK_CLSID) && is_shell_link_interface_iid(iid) {
            let shell_link_object = self.alloc_shell_link_object(memory)?;
            let interface_object = if iid.eq_ignore_ascii_case(IID_ISHELLLINKW)
                || iid.eq_ignore_ascii_case(IID_IUNKNOWN)
            {
                shell_link_object
            } else {
                self.ensure_shell_link_persist_file_object(memory, shell_link_object)?
            };
            return Ok(Some(interface_object));
        }
        // CLSID_WebBrowser / CLSID_InternetExplorer: the browser control.
        if clsid.eq_ignore_ascii_case("{8856F961-340A-11D0-A96B-00C04FD705A2}")
            || clsid.eq_ignore_ascii_case("{0002DF01-0000-0000-C000-000000000046}")
        {
            let object = self.alloc_web_browser_object(memory, "about:blank")?;
            return Ok(Some(object));
        }
        // CLSID_FilterGraph (DirectShow)
        if clsid.eq_ignore_ascii_case("{E436EBB3-524F-11CE-9F53-0020AF0BA770}") {
            let vtable = self.alloc_guest_vtable(memory, dshow_filter_graph_methods())?;
            let object =
                self.alloc_guest_object(memory, GuestObjectKind::DshowFilterGraph, vtable)?;
            return Ok(Some(object));
        }
        // DirectSound8 CLSID
        if clsid.eq_ignore_ascii_case("{3901CC3F-84B5-4FA4-BA35-AA8172B8A6B2}") {
            let methods = vec![
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                unsupported_method(&self.telemetry, "IDirectSound8::CreateSoundBuffer"),
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let object = self.alloc_guest_object(memory, GuestObjectKind::DirectSound8, vtable)?;
            return Ok(Some(object));
        }
        // CLSID_DirectPlay8Address ({934A9523-A3CA-4BC5-ADA0-D6D95D979421}):
        // a real IDirectPlay8Address object from the DirectPlay engine.
        if clsid.eq_ignore_ascii_case("{934A9523-A3CA-4BC5-ADA0-D6D95D979421}")
            && (iid.eq_ignore_ascii_case("{83783300-4063-4C8A-9DB3-82830A7FEB31}")
                || iid.eq_ignore_ascii_case(IID_IUNKNOWN))
        {
            return self.dplay_create_address_object(memory).map(Some);
        }
        // XAudio2 CLSID
        if clsid.eq_ignore_ascii_case("{609ED052-35B5-4F10-9BE6-39650F9781D4}") {
            let xaudio2_object = self.alloc_xaudio2_engine_object(memory)?;
            return Ok(Some(xaudio2_object));
        }
        // CLSID_FileOpenDialog / CLSID_FileSaveDialog
        if clsid.eq_ignore_ascii_case("{DC1C5A9C-E88A-4DDE-A5A1-60F82A20AEF7}")
            || clsid.eq_ignore_ascii_case("{C0B4E2F3-BA21-4773-8DBA-335EC946EB8B}")
        {
            let methods = vec![
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let object = self.alloc_guest_object(memory, GuestObjectKind::FileDialog, vtable)?;
            return Ok(Some(object));
        }
        // WMI CLSID: CLSID_WbemLocator ({4590F811-1D3A-11D0-891F-00AA004B2E24})
        if clsid.eq_ignore_ascii_case("{4590F811-1D3A-11D0-891F-00AA004B2E24}") {
            return self.alloc_wbem_locator_object(memory).map(Some);
        }
        // ── Phase L: COM/Shell Completion ──────────────────────────────────────
        // CLSID_ShellFolder ({00021400-0000-0000-C000-000000000046})
        if clsid.eq_ignore_ascii_case("{00021400-0000-0000-C000-000000000046}") {
            // IShellFolder vtable: [0]QI, [1]AddRef, [2]Release,
            // [3]ParseDisplayName, [4]EnumObjects, [5]BindToObject,
            // [6]BindToStorage, [7]CompareIDs, [8]CreateViewObject,
            // [9]GetAttributesOf, [10]GetUIObjectOf, [11]GetDisplayNameOf, [12]SetNameOf
            let telemetry = &self.telemetry;
            let methods = vec![
                HostThunk::GuestObjectAddRef,           // [0] QueryInterface
                HostThunk::GuestObjectAddRef,           // [1] AddRef
                HostThunk::GuestObjectRelease,          // [2] Release
                HostThunk::ShellFolderParseDisplayName, // [3] ParseDisplayName
                HostThunk::ShellFolderEnumObjects,      // [4] EnumObjects
                HostThunk::ShellFolderBindToObject,     // [5] BindToObject
                unsupported_method(telemetry, "IShellFolder::BindToStorage"), // [6]
                unsupported_method(telemetry, "IShellFolder::CompareIDs"), // [7]
                unsupported_method(telemetry, "IShellFolder::CreateViewObject"), // [8]
                HostThunk::ShellFolderGetAttributesOf,  // [9] GetAttributesOf
                HostThunk::ShellFolderGetUIObjectOf,    // [10] GetUIObjectOf
                HostThunk::ShellFolderGetDisplayNameOf, // [11] GetDisplayNameOf
                unsupported_method(telemetry, "IShellFolder::SetNameOf"), // [12]
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let object = self.alloc_guest_object(memory, GuestObjectKind::ShellFolder, vtable)?;
            // Register a default root path so that EnumObjects can enumerate
            // the filesystem when created via CoCreateInstance.
            self.shell_folder_paths.insert(object, "C:\\".to_string());
            return Ok(Some(object));
        }
        // CLSID_ShellContextMenu ({000214E4-0000-0000-C000-000000000046})
        if clsid.eq_ignore_ascii_case("{000214E4-0000-0000-C000-000000000046}") {
            // IContextMenu vtable: [0]QI, [1]AddRef, [2]Release,
            // [3]QueryContextMenu, [4]InvokeCommand, [5]GetCommandString
            let methods = vec![
                HostThunk::GuestObjectAddRef,           // [0] QueryInterface
                HostThunk::GuestObjectAddRef,           // [1] AddRef
                HostThunk::GuestObjectRelease,          // [2] Release
                HostThunk::ContextMenuQueryContextMenu, // [3] QueryContextMenu
                HostThunk::ContextMenuInvokeCommand,    // [4] InvokeCommand
                HostThunk::ContextMenuGetCommandString, // [5] GetCommandString
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let object = self.alloc_guest_object(memory, GuestObjectKind::ContextMenu, vtable)?;
            return Ok(Some(object));
        }
        // CLSID_PropertyStore ({886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99})
        if clsid.eq_ignore_ascii_case("{886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99}") {
            // IPropertyStore vtable: [0]QI, [1]AddRef, [2]Release,
            // [3]GetCount, [4]GetAt, [5]GetValue, [6]SetValue, [7]Commit
            let methods = vec![
                HostThunk::GuestObjectAddRef,     // [0] QueryInterface
                HostThunk::GuestObjectAddRef,     // [1] AddRef
                HostThunk::GuestObjectRelease,    // [2] Release
                HostThunk::PropertyStoreGetCount, // [3] GetCount
                HostThunk::PropertyStoreGetAt,    // [4] GetAt
                HostThunk::PropertyStoreGetValue, // [5] GetValue
                HostThunk::PropertyStoreSetValue, // [6] SetValue
                HostThunk::PropertyStoreCommit,   // [7] Commit
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let object = self.alloc_guest_object(memory, GuestObjectKind::PropertyStore, vtable)?;
            return Ok(Some(object));
        }
        // CLSID_DOMDocument ({2933BF90-7B36-11D2-B20E-00C04F983E60})
        if clsid.eq_ignore_ascii_case("{2933BF90-7B36-11D2-B20E-00C04F983E60}") {
            // IXMLDOMDocument —— large vtable (78+ methods). Wire the most commonly
            // used ones; fill the rest with unsupported stubs.
            let telemetry = &self.telemetry;
            let mut methods: Vec<HostThunk> = (0..78)
                .map(|i| unsupported_method(telemetry, &format!("IXMLDOMDocument::method_{i}")))
                .collect();
            methods[0] = HostThunk::GuestObjectAddRef; // QueryInterface
            methods[1] = HostThunk::GuestObjectAddRef; // AddRef
            methods[2] = HostThunk::GuestObjectRelease; // Release
            methods[51] = HostThunk::XmlDomLoadXml; // loadXML
            methods[56] = HostThunk::XmlDomGetDocumentElement; // get_documentElement
            methods[59] = HostThunk::XmlDomSelectNodes; // selectNodes (XPath)
            methods[60] = HostThunk::XmlDomCreateElement; // createElement
            methods[64] = HostThunk::XmlDomAppendChild; // appendChild
            methods[7] = HostThunk::XmlDomGetText; // get_nodeName
            methods[8] = HostThunk::XmlDomGetText; // get_nodeValue (same handler)
            methods[6] = HostThunk::XmlDomGetXml; // get_xml (slot 6)
            methods[58] = HostThunk::XmlDomGetElementsByTagName; // getElementsByTagName (slot 58)
            methods[61] = HostThunk::XmlDomTransformNode; // transformNode (slot 61)
            methods[62] = HostThunk::XmlDomCreateTextNode; // createTextNode (slot 62)
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let object =
                self.alloc_guest_object(memory, GuestObjectKind::XmlDomDocument, vtable)?;
            return Ok(Some(object));
        }
        // CLSID_UrlMoniker ({79EAC9E0-BAF9-11CE-8C82-00AA004BA90B})
        if clsid.eq_ignore_ascii_case("{79EAC9E0-BAF9-11CE-8C82-00AA004BA90B}") {
            // IMoniker vtable (the documented 18-slot layout plus the
            // runtime's appended BindIfRunning slot)
            let methods = vec![
                HostThunk::GuestObjectAddRef,                       // [0] QueryInterface
                HostThunk::GuestObjectAddRef,                       // [1] AddRef
                HostThunk::GuestObjectRelease,                      // [2] Release
                HostThunk::ComMethod(ComMethod::MonikerGetClassID), // [3]
                HostThunk::ComMethod(ComMethod::MonikerIsDirty),    // [4]
                HostThunk::ComMethod(ComMethod::MonikerLoad),       // [5]
                HostThunk::ComMethod(ComMethod::MonikerSave),       // [6]
                HostThunk::ComMethod(ComMethod::MonikerGetSizeMax), // [7]
                HostThunk::MonikerBindToObject,                     // [8] BindToObject
                HostThunk::MonikerBindToStorage,                    // [9] BindToStorage
                HostThunk::MonikerReduce,                           // [10] Reduce
                HostThunk::MonikerComposeWith,                      // [11] ComposeWith
                HostThunk::MonikerEnum,                             // [12] Enum
                HostThunk::ComMethod(ComMethod::MonikerIsEqual),    // [13]
                HostThunk::MonikerGetDisplayName,                   // [14] GetDisplayName
                HostThunk::ComMethod(ComMethod::MonikerParseDisplayName), // [15]
                HostThunk::MonikerIsSystemMoniker,                  // [16] IsSystemMoniker
                HostThunk::MonikerHash,                             // [17] Hash
                HostThunk::ComMethod(ComMethod::MonikerBindIfRunning), // [18]
            ];
            let vtable = self.alloc_guest_vtable(memory, methods)?;
            let object = self.alloc_guest_object(memory, GuestObjectKind::UrlMoniker, vtable)?;
            return Ok(Some(object));
        }
        // CLSID not recognised — caller should return CLASS_E_CLASSNOTAVAILABLE
        Ok(None)
    }

    /// Lazily initialise the native COM apartment state if it hasn't been
    /// created yet.  Returns a mutable reference to the apartment state.
    pub(crate) fn ensure_com_apartment(&mut self) -> &mut crate::real_win32::ComApartmentState {
        self.com_apartment
            .get_or_insert_with(crate::real_win32::ComApartmentState::new)
    }

    /// Allocate a guest COM class factory object with IClassFactory vtable.
    ///
    /// The vtable has 5 entries:
    ///   [0] QueryInterface  → GuestObjectAddRef
    ///   [1] AddRef          → GuestObjectAddRef
    ///   [2] Release         → GuestObjectRelease
    ///   [3] CreateInstance  → ComFactoryCreateInstance
    ///   [4] LockServer      → ComFactoryLockServer
    pub(crate) fn alloc_com_factory_object(
        &mut self,
        memory: &mut MemoryImage,
        clsid: &str,
    ) -> AppResult<u64> {
        let methods = vec![
            HostThunk::GuestObjectAddRef,        // QueryInterface
            HostThunk::GuestObjectAddRef,        // AddRef
            HostThunk::GuestObjectRelease,       // Release
            HostThunk::ComFactoryCreateInstance, // CreateInstance
            HostThunk::ComFactoryLockServer,     // LockServer
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::ComClassFactory, vtable)?;
        self.com_factory_clsids.insert(object, clsid.to_string());
        Ok(object)
    }

    pub(crate) fn alloc_shell_link_object(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        let mut methods = vec![unsupported_method(&self.telemetry, "IShellLinkW::reserved"); 21];
        methods[0] = HostThunk::ShellLinkQueryInterface;
        methods[1] = HostThunk::ShellLinkAddRef;
        methods[2] = HostThunk::ShellLinkRelease;
        methods[3] = HostThunk::ShellLinkGetPathW;
        methods[4] = HostThunk::ShellLinkGetIDList;
        methods[5] = HostThunk::ShellLinkSetIDList;
        methods[6] = HostThunk::ShellLinkGetDescriptionW;
        methods[7] = HostThunk::ShellLinkSetDescriptionW;
        methods[8] = HostThunk::ShellLinkGetWorkingDirectoryW;
        methods[9] = HostThunk::ShellLinkSetWorkingDirectoryW;
        methods[10] = HostThunk::ShellLinkGetArgumentsW;
        methods[11] = HostThunk::ShellLinkSetArgumentsW;
        methods[12] = HostThunk::ShellLinkGetHotkey;
        methods[13] = HostThunk::ShellLinkSetHotkey;
        methods[14] = HostThunk::ShellLinkGetShowCmd;
        methods[15] = HostThunk::ShellLinkSetShowCmd;
        methods[16] = HostThunk::ShellLinkGetIconLocationW;
        methods[17] = HostThunk::ShellLinkSetIconLocationW;
        methods[18] = HostThunk::ShellLinkSetRelativePath;
        methods[19] = HostThunk::ShellLinkResolve;
        methods[20] = HostThunk::ShellLinkSetPathW;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object =
            self.alloc_guest_object(memory, GuestObjectKind::ShellLinkInterface, vtable)?;
        self.shell_link_interfaces.insert(
            object,
            GuestShellLinkInterface {
                state_id: object,
                kind: ShellLinkInterfaceKind::ShellLinkW,
            },
        );
        self.shell_link_states.insert(
            object,
            GuestShellLinkState {
                shell_link_object: object,
                persist_file_object: None,
                refcount: 1,
                path: String::new(),
                arguments: String::new(),
                description: String::new(),
                working_directory: String::new(),
                relative_path: String::new(),
                hotkey: 0,
                icon_location: String::new(),
                icon_index: 0,
                show_cmd: SW_SHOWNORMAL,
                current_file: None,
                dirty: false,
            },
        );
        Ok(object)
    }

    pub(crate) fn ensure_shell_link_persist_file_object(
        &mut self,
        memory: &mut MemoryImage,
        shell_link_object: u64,
    ) -> AppResult<u64> {
        let state_id = self.shell_link_interface(shell_link_object)?.state_id;
        if let Some(object) = self.shell_link_state(state_id)?.persist_file_object {
            return Ok(object);
        }
        let mut methods = vec![unsupported_method(&self.telemetry, "IPersistFile::reserved"); 9];
        methods[0] = HostThunk::ShellLinkQueryInterface;
        methods[1] = HostThunk::ShellLinkAddRef;
        methods[2] = HostThunk::ShellLinkRelease;
        methods[3] = HostThunk::ShellLinkPersistGetClassID;
        methods[4] = HostThunk::ShellLinkPersistIsDirty;
        methods[5] = HostThunk::ShellLinkPersistLoad;
        methods[6] = HostThunk::ShellLinkPersistSave;
        methods[7] = HostThunk::ShellLinkPersistSaveCompleted;
        methods[8] = HostThunk::ShellLinkPersistGetCurFile;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object =
            self.alloc_guest_object(memory, GuestObjectKind::ShellLinkInterface, vtable)?;
        self.shell_link_interfaces.insert(
            object,
            GuestShellLinkInterface {
                state_id,
                kind: ShellLinkInterfaceKind::PersistFile,
            },
        );
        self.shell_link_state_mut(state_id)?.persist_file_object = Some(object);
        Ok(object)
    }

    pub(crate) fn shell_link_interface(&self, address: u64) -> AppResult<GuestShellLinkInterface> {
        self.shell_link_interfaces
            .get(&address)
            .copied()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unknown shell link interface object {address:#x}"),
                )
            })
    }

    pub(crate) fn shell_link_state(&self, state_id: u64) -> AppResult<&GuestShellLinkState> {
        self.shell_link_states.get(&state_id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown shell link state {state_id:#x}"),
            )
        })
    }

    pub(crate) fn shell_link_state_mut(
        &mut self,
        state_id: u64,
    ) -> AppResult<&mut GuestShellLinkState> {
        self.shell_link_states.get_mut(&state_id).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown shell link state {state_id:#x}"),
            )
        })
    }

    pub(crate) fn shell_link_state_for_interface(
        &self,
        address: u64,
    ) -> AppResult<&GuestShellLinkState> {
        let interface = self.shell_link_interface(address)?;
        self.shell_link_state(interface.state_id)
    }

    pub(crate) fn shell_link_state_for_interface_mut(
        &mut self,
        address: u64,
    ) -> AppResult<&mut GuestShellLinkState> {
        let interface = self.shell_link_interface(address)?;
        self.shell_link_state_mut(interface.state_id)
    }

    pub(crate) fn add_ref_shell_link_object(&mut self, address: u64) -> AppResult<u32> {
        let state_id = self.shell_link_interface(address)?.state_id;
        let state = self.shell_link_state_mut(state_id)?;
        state.refcount = state.refcount.saturating_add(1);
        Ok(state.refcount)
    }

    pub(crate) fn release_shell_link_object(&mut self, address: u64) -> AppResult<u32> {
        let state_id = self.shell_link_interface(address)?.state_id;
        let refcount = {
            let state = self.shell_link_state_mut(state_id)?;
            state.refcount = state.refcount.saturating_sub(1);
            state.refcount
        };
        if refcount == 0 {
            self.destroy_shell_link_state(state_id)?;
        }
        Ok(refcount)
    }

    pub(crate) fn destroy_shell_link_interface_object(&mut self, address: u64) -> AppResult<()> {
        let state_id = self.shell_link_interface(address)?.state_id;
        self.destroy_shell_link_state(state_id)
    }

    pub(crate) fn destroy_shell_link_state(&mut self, state_id: u64) -> AppResult<()> {
        if let Some(state) = self.shell_link_states.remove(&state_id) {
            self.shell_link_interfaces.remove(&state.shell_link_object);
            self.guest_objects.remove(&state.shell_link_object);
            if let Some(persist_file_object) = state.persist_file_object {
                self.shell_link_interfaces.remove(&persist_file_object);
                self.guest_objects.remove(&persist_file_object);
            }
        }
        Ok(())
    }

    pub(crate) fn shell_link_query_interface(
        &mut self,
        memory: &mut MemoryImage,
        address: u64,
        iid: &str,
        out_ptr: u64,
    ) -> AppResult<u64> {
        if out_ptr == 0 {
            return Ok(E_INVALIDARG);
        }
        write_guest_pointer(memory, out_ptr, 0, self.guest_arch)?;
        let interface = self.shell_link_interface(address)?;
        let state_id = interface.state_id;
        let object = if iid.eq_ignore_ascii_case(IID_IUNKNOWN)
            || iid.eq_ignore_ascii_case(IID_ISHELLLINKW)
        {
            self.shell_link_state(state_id)?.shell_link_object
        } else if iid.eq_ignore_ascii_case(IID_IPERSIST)
            || iid.eq_ignore_ascii_case(IID_IPERSISTFILE)
        {
            let shell_link_object = self.shell_link_state(state_id)?.shell_link_object;
            self.ensure_shell_link_persist_file_object(memory, shell_link_object)?
        } else {
            return Ok(E_NOINTERFACE);
        };
        self.add_ref_shell_link_object(object)?;
        write_guest_pointer(memory, out_ptr, object, self.guest_arch)?;
        Ok(0)
    }

    pub(crate) fn set_shell_link_path(&mut self, address: u64, value: String) -> AppResult<()> {
        let state = self.shell_link_state_for_interface_mut(address)?;
        state.path = value;
        state.dirty = true;
        Ok(())
    }

    pub(crate) fn set_shell_link_arguments(
        &mut self,
        address: u64,
        value: String,
    ) -> AppResult<()> {
        let state = self.shell_link_state_for_interface_mut(address)?;
        state.arguments = value;
        state.dirty = true;
        Ok(())
    }

    pub(crate) fn set_shell_link_description(
        &mut self,
        address: u64,
        value: String,
    ) -> AppResult<()> {
        let state = self.shell_link_state_for_interface_mut(address)?;
        state.description = value;
        state.dirty = true;
        Ok(())
    }

    pub(crate) fn set_shell_link_working_directory(
        &mut self,
        address: u64,
        value: String,
    ) -> AppResult<()> {
        let state = self.shell_link_state_for_interface_mut(address)?;
        state.working_directory = value;
        state.dirty = true;
        Ok(())
    }

    pub(crate) fn set_shell_link_icon_location(
        &mut self,
        address: u64,
        value: String,
        icon_index: i32,
    ) -> AppResult<()> {
        let state = self.shell_link_state_for_interface_mut(address)?;
        state.icon_location = value;
        state.icon_index = icon_index;
        state.dirty = true;
        Ok(())
    }

    pub(crate) fn set_shell_link_show_cmd(&mut self, address: u64, show_cmd: i32) -> AppResult<()> {
        let state = self.shell_link_state_for_interface_mut(address)?;
        state.show_cmd = show_cmd;
        state.dirty = true;
        Ok(())
    }

    pub(crate) fn save_shell_link(
        &mut self,
        address: u64,
        requested_path: Option<&str>,
        remember: bool,
    ) -> AppResult<u64> {
        let snapshot = self.shell_link_state_for_interface(address)?.clone();
        if snapshot.path.is_empty() {
            return Ok(E_INVALIDARG);
        }
        let save_path = if let Some(path) = requested_path {
            resolve_guest_path(&self.current_directory, path)
        } else if let Some(path) = snapshot.current_file.clone() {
            path
        } else {
            return Ok(E_INVALIDARG);
        };
        let bytes = self.shell_link_file_bytes(&snapshot)?;
        match self.win32.write_file_overwrite_w(&save_path, &bytes) {
            Ok(_) => {
                let state = self.shell_link_state_for_interface_mut(address)?;
                if remember || state.current_file.is_none() {
                    state.current_file = Some(save_path);
                }
                state.dirty = false;
                Ok(0)
            }
            Err(_) => Ok(E_ACCESSDENIED),
        }
    }

    pub(crate) fn complete_shell_link_save(
        &mut self,
        address: u64,
        completed_path: Option<String>,
    ) -> AppResult<()> {
        let state = self.shell_link_state_for_interface_mut(address)?;
        if let Some(path) = completed_path {
            state.current_file = Some(path);
        }
        state.dirty = false;
        Ok(())
    }

    /// Load a persisted shell link into the object's state.  The parser is
    /// the same `src/lnk.rs` reader the writer's round-trip tests use: a
    /// structurally invalid stream is `E_FAIL`, an unreadable path keeps the
    /// file layer's honest failure.
    pub(crate) fn load_shell_link(&mut self, address: u64, guest_path: &str) -> AppResult<u64> {
        let host_path = match self.win32.guest_path_to_host_path(guest_path) {
            Ok(path) => path,
            Err(_) => return Ok(0x8000_4005),
        };
        let bytes = match fs::read(&host_path) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(0x8000_4005),
        };
        let Some(parsed) = crate::lnk::parse(&bytes) else {
            return Ok(0x8000_4005);
        };
        let Some(target) = parsed.target_path else {
            return Ok(0x8000_4005);
        };
        let state = self.shell_link_state_for_interface_mut(address)?;
        state.path = target;
        state.description = parsed.description.unwrap_or_default();
        state.relative_path = parsed.relative_path.unwrap_or_default();
        state.working_directory = parsed.working_directory.unwrap_or_default();
        state.arguments = parsed.arguments.unwrap_or_default();
        state.icon_location = parsed.icon_location.unwrap_or_default();
        state.icon_index = parsed.icon_index;
        state.show_cmd = parsed.show_cmd;
        state.hotkey = parsed.hotkey;
        state.current_file = Some(guest_path.to_string());
        state.dirty = false;
        Ok(0)
    }

    /// Resolve a shell link's target: the stored path wins when it exists;
    /// otherwise the stored relative path is resolved against the link file's
    /// directory (then the working directory) and committed when it exists.
    /// A genuinely unresolvable link reports `S_FALSE`.
    pub(crate) fn resolve_shell_link(&mut self, address: u64) -> AppResult<u32> {
        let snapshot = self.shell_link_state_for_interface(address)?.clone();
        if !snapshot.path.is_empty()
            && self
                .win32
                .guest_path_to_host_path(&snapshot.path)
                .is_ok_and(|path| path.exists())
        {
            return Ok(0);
        }
        if snapshot.relative_path.is_empty() {
            return Ok(1);
        }
        let mut bases = Vec::new();
        if let Some(current_file) = &snapshot.current_file {
            if let Some((dir, _)) = current_file.rsplit_once('\\') {
                bases.push(dir.to_string());
            }
        }
        if !snapshot.working_directory.is_empty() {
            bases.push(snapshot.working_directory.clone());
        }
        if bases.is_empty() {
            bases.push(self.current_directory.clone());
        }
        for base in bases {
            let candidate = resolve_guest_path(&base, &snapshot.relative_path);
            if self
                .win32
                .guest_path_to_host_path(&candidate)
                .is_ok_and(|path| path.exists())
            {
                let state = self.shell_link_state_for_interface_mut(address)?;
                state.path = candidate;
                state.dirty = true;
                return Ok(0);
            }
        }
        Ok(1)
    }

    pub(crate) fn shell_link_file_bytes(&self, state: &GuestShellLinkState) -> AppResult<Vec<u8>> {
        let target_attributes = self
            .win32
            .get_file_attributes_w(&state.path)
            .map(|attributes| file_attributes_mask(&attributes))
            .unwrap_or(FILE_ATTRIBUTE_NORMAL);
        let target_size = self
            .win32
            .guest_path_to_host_path(&state.path)
            .ok()
            .and_then(|host_path| fs::metadata(host_path).ok())
            .map(|metadata| {
                if metadata.is_dir() {
                    0
                } else {
                    metadata.len().min(u64::from(u32::MAX)) as u32
                }
            })
            .unwrap_or(0);
        let target_write_time = self
            .win32
            .ge()
            .get_file_metadata(&state.path)
            .map(|metadata| metadata.last_write_time_ticks)
            .unwrap_or(0);
        // The canonical shell-link writer (src/lnk.rs) — the same bytes
        // the SHCreateLinks export and every IPersistFile::Save produce.
        Ok(crate::lnk::encode(&crate::lnk::ShellLinkData {
            target_path: state.path.clone(),
            description: state.description.clone(),
            relative_path: state.relative_path.clone(),
            working_directory: state.working_directory.clone(),
            arguments: state.arguments.clone(),
            icon_location: state.icon_location.clone(),
            icon_index: state.icon_index,
            show_cmd: state.show_cmd,
            file_attributes: target_attributes,
            file_size: target_size,
            write_time_ticks: target_write_time,
        }))
    }

    pub(crate) fn alloc_xaudio2_engine_object(
        &mut self,
        memory: &mut MemoryImage,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(
            memory,
            vec![
                unsupported_method(&self.telemetry, "IXAudio2::QueryInterface"),
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                // RegisterForCallbacks — no-op: callbacks are not supported
                HostThunk::XAudio2RegisterForCallbacks,
                // UnregisterForCallbacks — no-op
                HostThunk::XAudio2UnregisterForCallbacks,
                HostThunk::XAudio2CreateSourceVoice,
                HostThunk::XAudio2CreateSubmixVoice,
                HostThunk::XAudio2CreateMasteringVoice,
                HostThunk::XAudio2StartEngine,
                HostThunk::XAudio2StopEngine,
                HostThunk::XAudio2CommitChanges,
                // GetPerformanceData — return zero (no data collected)
                HostThunk::XAudio2GetPerformanceData,
                // SetDebugConfiguration — no-op
                HostThunk::XAudio2SetDebugConfiguration,
            ],
        )?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::XAudio2Engine, vtable)?;
        self.xaudio_engines.insert(
            object,
            GuestXAudio2Engine {
                mastering_voice: None,
                source_voices: Vec::new(),
            },
        );
        Ok(object)
    }

    pub(crate) fn alloc_xaudio2_mastering_voice_object(
        &mut self,
        memory: &mut MemoryImage,
        engine_object: u64,
        voice_id: VoiceId,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(
            memory,
            vec![
                HostThunk::XAudio2VoiceGetVoiceDetails,
                HostThunk::XAudio2VoiceSetOutputVoices,
                HostThunk::XAudio2VoiceSetEffectChain,
                HostThunk::XAudio2VoiceEnableEffect,
                HostThunk::XAudio2VoiceDisableEffect,
                HostThunk::XAudio2VoiceGetEffectState,
                HostThunk::XAudio2VoiceSetEffectParameters,
                HostThunk::XAudio2VoiceGetEffectParameters,
                HostThunk::XAudio2VoiceSetFilterParameters,
                HostThunk::XAudio2VoiceGetFilterParameters,
                HostThunk::XAudio2VoiceSetOutputFilterParameters,
                HostThunk::XAudio2VoiceGetOutputFilterParameters,
                HostThunk::XAudio2VoiceSetVolume,
                HostThunk::XAudio2VoiceGetVolume,
                HostThunk::XAudio2VoiceSetChannelVolumes,
                HostThunk::XAudio2VoiceGetChannelVolumes,
                HostThunk::XAudio2VoiceSetOutputMatrix,
                HostThunk::XAudio2VoiceGetOutputMatrix,
                HostThunk::XAudio2VoiceDestroyVoice,
            ],
        )?;
        let object =
            self.alloc_guest_object(memory, GuestObjectKind::XAudio2MasteringVoice, vtable)?;
        self.xaudio_mastering_voices.insert(
            object,
            GuestXAudio2Voice {
                engine_object,
                voice_id,
            },
        );
        Ok(object)
    }

    pub(crate) fn alloc_xaudio2_source_voice_object(
        &mut self,
        memory: &mut MemoryImage,
        engine_object: u64,
        voice_id: VoiceId,
    ) -> AppResult<u64> {
        let vtable = self.alloc_guest_vtable(
            memory,
            vec![
                HostThunk::XAudio2VoiceGetVoiceDetails,
                HostThunk::XAudio2VoiceSetOutputVoices,
                HostThunk::XAudio2VoiceSetEffectChain,
                HostThunk::XAudio2VoiceEnableEffect,
                HostThunk::XAudio2VoiceDisableEffect,
                HostThunk::XAudio2VoiceGetEffectState,
                HostThunk::XAudio2VoiceSetEffectParameters,
                HostThunk::XAudio2VoiceGetEffectParameters,
                HostThunk::XAudio2VoiceSetFilterParameters,
                HostThunk::XAudio2VoiceGetFilterParameters,
                HostThunk::XAudio2VoiceSetOutputFilterParameters,
                HostThunk::XAudio2VoiceGetOutputFilterParameters,
                HostThunk::XAudio2VoiceSetVolume,
                HostThunk::XAudio2VoiceGetVolume,
                HostThunk::XAudio2VoiceSetChannelVolumes,
                HostThunk::XAudio2VoiceGetChannelVolumes,
                HostThunk::XAudio2VoiceSetOutputMatrix,
                HostThunk::XAudio2VoiceGetOutputMatrix,
                HostThunk::XAudio2VoiceDestroyVoice,
                HostThunk::XAudio2SourceVoiceStart,
                HostThunk::XAudio2SourceVoiceStop,
                HostThunk::XAudio2SourceVoiceSubmitSourceBuffer,
                HostThunk::XAudio2SourceVoiceFlushSourceBuffers,
                HostThunk::XAudio2SourceVoiceDiscontinuity,
                HostThunk::XAudio2SourceVoiceExitLoop,
                HostThunk::XAudio2SourceVoiceGetState,
                HostThunk::XAudio2SourceVoiceSetFrequencyRatio,
                HostThunk::XAudio2SourceVoiceGetFrequencyRatio,
                HostThunk::XAudio2SourceVoiceSetSourceSampleRate,
            ],
        )?;
        let object =
            self.alloc_guest_object(memory, GuestObjectKind::XAudio2SourceVoice, vtable)?;
        self.xaudio_source_voices.insert(
            object,
            GuestXAudio2Voice {
                engine_object,
                voice_id,
            },
        );
        Ok(object)
    }

    pub(crate) fn destroy_xaudio2_engine_object(&mut self, address: u64) -> AppResult<()> {
        let engine = self.xaudio_engines.remove(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown XAudio2 engine {address:#x}"),
            )
        })?;
        for source in engine.source_voices {
            let _ = self.destroy_xaudio2_voice_object(source);
        }
        if let Some(mastering_voice) = engine.mastering_voice {
            let _ = self.destroy_xaudio2_voice_object(mastering_voice);
        }
        self.guest_objects.remove(&address);
        Ok(())
    }

    pub(crate) fn destroy_xaudio2_voice_object(&mut self, address: u64) -> AppResult<()> {
        if let Some(voice) = self.xaudio_source_voices.remove(&address) {
            self.audio.destroy_voice(voice.voice_id)?;
            if let Some(engine) = self.xaudio_engines.get_mut(&voice.engine_object) {
                engine
                    .source_voices
                    .retain(|candidate| *candidate != address);
            }
            self.guest_objects.remove(&address);
            return Ok(());
        }
        if let Some(voice) = self.xaudio_mastering_voices.remove(&address) {
            let dependent_sources = self
                .xaudio_engines
                .get(&voice.engine_object)
                .map(|engine| engine.source_voices.clone())
                .unwrap_or_default();
            for source in dependent_sources {
                let _ = self.destroy_xaudio2_voice_object(source);
            }
            self.audio.destroy_voice(voice.voice_id)?;
            if let Some(engine) = self.xaudio_engines.get_mut(&voice.engine_object) {
                engine.mastering_voice = None;
                engine.source_voices.clear();
            }
            self.guest_objects.remove(&address);
            return Ok(());
        }
        Err(AppError::new(
            ReasonCode::RcUnimplInsn,
            format!("unknown XAudio2 voice object {address:#x}"),
        ))
    }

    pub(crate) fn xaudio_engine(&self, address: u64) -> AppResult<&GuestXAudio2Engine> {
        self.xaudio_engines.get(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown XAudio2 engine {address:#x}"),
            )
        })
    }

    pub(crate) fn xaudio_engine_mut(&mut self, address: u64) -> AppResult<&mut GuestXAudio2Engine> {
        self.xaudio_engines.get_mut(&address).ok_or_else(|| {
            AppError::new(
                ReasonCode::RcUnimplInsn,
                format!("unknown XAudio2 engine {address:#x}"),
            )
        })
    }

    pub(crate) fn xaudio_source_voice(&self, address: u64) -> AppResult<GuestXAudio2Voice> {
        self.xaudio_source_voices
            .get(&address)
            .copied()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unknown XAudio2 source voice {address:#x}"),
                )
            })
    }

    pub(crate) fn xaudio_mastering_voice(&self, address: u64) -> AppResult<GuestXAudio2Voice> {
        self.xaudio_mastering_voices
            .get(&address)
            .copied()
            .ok_or_else(|| {
                AppError::new(
                    ReasonCode::RcUnimplInsn,
                    format!("unknown XAudio2 mastering voice {address:#x}"),
                )
            })
    }

    pub(crate) fn drain_xaudio2_engine(&mut self, engine_object: u64) -> AppResult<()> {
        let (mastering_object, source_objects) = {
            let engine = self.xaudio_engine(engine_object)?;
            (engine.mastering_voice, engine.source_voices.clone())
        };
        let Some(mastering_object) = mastering_object else {
            return Ok(());
        };
        let mastering_voice = self.xaudio_mastering_voice(mastering_object)?;
        let mut frames = 0_usize;
        for source_object in &source_objects {
            if let Some(source) = self.xaudio_source_voices.get(source_object)
                && self.audio.voice_started(source.voice_id)?
            {
                frames = frames.max(self.audio.queued_source_frames(source.voice_id)?);
            }
        }
        if frames == 0 {
            return Ok(());
        }
        let format = self.audio.voice_format(mastering_voice.voice_id)?;
        let output = self
            .audio
            .render_xaudio2(mastering_voice.voice_id, frames)?;
        if self.live_session.is_some() && output.samples.iter().any(|sample| *sample != 0.0) {
            self.publish_live_audio(LiveAudioChunk {
                format: format.clone(),
                samples: output.samples.clone(),
            });
        } else if !self.dtm && output.samples.iter().any(|sample| *sample != 0.0) {
            self.audio.play_render_output(&output, &format)?;
        }
        self.push_trace(
            "audio",
            "XAudio2Render",
            BTreeMap::from([
                ("frames".to_string(), json!(frames)),
                ("latency_ms".to_string(), json!(output.latency_ms)),
                ("callbacks".to_string(), json!(output.voice_callbacks.len())),
            ]),
            json!(output.crc32),
        );
        Ok(())
    }

    /// Allocate a guest COM object implementing the IXAPO interface.
    ///
    /// IXAPO vtable layout (7 entries):
    ///   [0] QueryInterface              → GuestObjectAddRef
    ///   [1] AddRef                      → GuestObjectAddRef
    ///   [2] Release                     → GuestObjectRelease
    ///   [3] GetRegistrationProperties   → XAPO_GetRegistrationProperties
    ///   [4] LockForProcess              → XAPO_LockForProcess
    ///   [5] UnlockForProcess            → XAPO_UnlockForProcess
    ///   [6] Process                     → XAPO_Process
    #[allow(dead_code)] // XAudio2 XAPO effect allocation; used by tests
    pub(crate) fn alloc_xapo_effect_object(
        &mut self,
        memory: &mut MemoryImage,
        clsid: &[u8; 16],
    ) -> AppResult<Option<u64>> {
        let instance_id = match self
            .xapo_manager
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .create_instance(clsid)
        {
            Some(id) => id,
            None => return Ok(None),
        };
        let vtable = self.alloc_guest_vtable(
            memory,
            vec![
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectAddRef,
                HostThunk::GuestObjectRelease,
                HostThunk::XAPO_GetRegistrationProperties,
                HostThunk::XAPO_LockForProcess,
                HostThunk::XAPO_UnlockForProcess,
                HostThunk::XAPO_Process,
            ],
        )?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::XapoEffect, vtable)?;
        self.xapo_effect_instances.insert(object, instance_id);
        Ok(Some(object))
    }

    pub(crate) fn destroy_xapo_effect_object(&mut self, address: u64) -> AppResult<()> {
        if let Some(instance_id) = self.xapo_effect_instances.remove(&address) {
            self.xapo_manager
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .destroy_instance(instance_id);
        }
        self.guest_objects.remove(&address);
        Ok(())
    }

    // ── WMI COM Object Allocation ────────────────────────────────────────────────

    /// Allocate a WbemLocator guest COM object with IWbemLocator vtable.
    ///
    /// IWbemLocator vtable layout:
    ///   [0] QueryInterface  → GuestObjectAddRef
    ///   [1] AddRef          → GuestObjectAddRef
    ///   [2] Release         → GuestObjectRelease
    ///   [3] ConnectServer   → WbemLocatorConnectServer
    pub(crate) fn alloc_wbem_locator_object(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        let methods = vec![
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::WbemLocatorConnectServer,
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::WbemLocator, vtable)?;
        self.wmi_services
            .insert(object, crate::wmi::WbemServices::new());
        Ok(object)
    }

    /// Allocate a WbemServices guest COM object with IWbemServices vtable.
    ///
    /// IWbemServices vtable layout:
    ///   [0] QueryInterface       → GuestObjectAddRef
    ///   [1] AddRef               → GuestObjectAddRef
    ///   [2] Release              → GuestObjectRelease
    ///   [3] ExecQuery            → WbemServicesExecQuery
    ///   [4] CreateInstanceEnum   → WbemServicesCreateInstanceEnum
    ///   [5] GetObject            → WbemServicesGetObject
    pub(crate) fn alloc_wbem_services_object(
        &mut self,
        memory: &mut MemoryImage,
    ) -> AppResult<u64> {
        let methods = vec![
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::WbemServicesExecQuery,
            HostThunk::WbemServicesCreateInstanceEnum,
            HostThunk::WbemServicesGetObject,
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::WbemServices, vtable)?;
        self.wmi_services
            .insert(object, crate::wmi::WbemServices::new());
        Ok(object)
    }

    /// Allocate a WbemClassObject guest COM object with IWbemClassObject vtable.
    ///
    /// IWbemClassObject vtable layout:
    ///   [0] QueryInterface  → GuestObjectAddRef
    ///   [1] AddRef          → GuestObjectAddRef
    ///   [2] Release         → GuestObjectRelease
    ///   [3] Get             → WbemClassObjectGet
    ///   [4] Put             → WbemClassObjectPut
    ///   [5] GetNames        → WbemClassObjectGetNames
    ///   [6] GetObjectText   → WbemClassObjectGetObjectText
    pub(crate) fn alloc_wbem_class_object(
        &mut self,
        memory: &mut MemoryImage,
        class_object: crate::wmi::WbemClassObject,
    ) -> AppResult<u64> {
        let methods = vec![
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::WbemClassObjectGet,
            HostThunk::WbemClassObjectPut,
            HostThunk::WbemClassObjectGetNames,
            HostThunk::WbemClassObjectGetObjectText,
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::WbemClassObject, vtable)?;
        self.wmi_class_objects.insert(object, class_object);
        Ok(object)
    }

    /// Allocate an EnumWbemObjects guest COM object with IEnumWbemClassObject vtable.
    ///
    /// IEnumWbemClassObject vtable layout:
    ///   [0] QueryInterface  → GuestObjectAddRef
    ///   [1] AddRef          → GuestObjectAddRef
    ///   [2] Release         → GuestObjectRelease
    ///   [3] Next            → EnumWbemClassObjectNext
    ///   [4] Skip            → EnumWbemClassObjectSkip
    ///   [5] Reset           → EnumWbemClassObjectReset
    ///   [6] Clone           → EnumWbemClassObjectClone
    pub(crate) fn alloc_enum_wbem_objects(
        &mut self,
        memory: &mut MemoryImage,
        enum_objects: crate::wmi::EnumWbemObjects,
    ) -> AppResult<u64> {
        let methods = vec![
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectAddRef,
            HostThunk::GuestObjectRelease,
            HostThunk::EnumWbemClassObjectNext,
            HostThunk::EnumWbemClassObjectSkip,
            HostThunk::EnumWbemClassObjectReset,
            HostThunk::EnumWbemClassObjectClone,
        ];
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::EnumWbemObjects, vtable)?;
        self.wmi_enums.insert(object, enum_objects);
        Ok(object)
    }

    pub(crate) fn alloc_directinput8_object(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        // IDirectInput8W vtable layout:
        //   0: QueryInterface, 1: AddRef, 2: Release,
        //   3: CreateDevice, 4: EnumDevices, 5: GetDeviceStatus,
        //   6: RunControlPanel, 7: Initialize
        let mut methods =
            vec![unsupported_method(&self.telemetry, "IDirectInput8W::unsupported"); 10];
        methods[0] = unsupported_method(&self.telemetry, "IDirectInput8W::QueryInterface");
        methods[1] = HostThunk::GuestObjectAddRef;
        methods[2] = HostThunk::GuestObjectRelease;
        methods[3] = HostThunk::DirectInput8CreateDevice;
        methods[4] = HostThunk::DirectInput8EnumDevices;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::DirectInput8, vtable)?;
        self.directinput8_objects.insert(object, ());
        Ok(object)
    }

    pub(crate) fn alloc_directinput8_device_object(
        &mut self,
        memory: &mut MemoryImage,
        guid: String,
    ) -> AppResult<u64> {
        // IDirectInputDevice8W vtable layout (~27 methods):
        //   0: QueryInterface, 1: AddRef, 2: Release,
        //   3: GetCapabilities, 4: EnumObjects, 5: GetProperty, 6: SetProperty,
        //   7: Acquire, 8: Unacquire, 9: GetDeviceState, 10: GetDeviceData,
        //   11: SetDataFormat, 12: SetCooperativeLevel,
        //   13-23: other methods (stubbed),
        //   24: Poll
        let mut methods =
            vec![unsupported_method(&self.telemetry, "IDirectInputDevice8W::unsupported"); 28];
        methods[0] = unsupported_method(&self.telemetry, "IDirectInputDevice8W::QueryInterface");
        methods[1] = HostThunk::GuestObjectAddRef;
        methods[2] = HostThunk::GuestObjectRelease;
        methods[3] = HostThunk::DirectInputDevice8GetCapabilities;
        methods[4] = HostThunk::DirectInputDevice8EnumObjects;
        methods[6] = HostThunk::DirectInputDevice8SetProperty;
        methods[7] = HostThunk::DirectInputDevice8Acquire;
        methods[8] = HostThunk::DirectInputDevice8Unacquire;
        methods[9] = HostThunk::DirectInputDevice8GetDeviceState;
        methods[10] = HostThunk::DirectInputDevice8GetDeviceData;
        methods[11] = HostThunk::DirectInputDevice8SetDataFormat;
        methods[12] = HostThunk::DirectInputDevice8SetCooperativeLevel;
        // Force-feedback vtable slots (IDirectInputDevice8 methods 21 and 22)
        methods[21] = HostThunk::DirectInputDevice8SendForceFeedbackCommand;
        methods[22] = HostThunk::DirectInputDevice8SetForceFeedbackState;
        methods[24] = HostThunk::DirectInputDevice8Poll;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object =
            self.alloc_guest_object(memory, GuestObjectKind::DirectInput8Device, vtable)?;
        self.directinput8_device_objects.insert(object, guid);
        Ok(object)
    }

    pub(crate) fn destroy_directinput8_object(&mut self, address: u64) -> AppResult<()> {
        self.directinput8_objects.remove(&address);
        self.guest_objects.remove(&address);
        Ok(())
    }

    pub(crate) fn destroy_directinput8_device_object(&mut self, address: u64) -> AppResult<()> {
        self.directinput8_device_objects.remove(&address);
        self.guest_objects.remove(&address);
        Ok(())
    }

    // ── SteamVR vtable allocators (Phase 5.3.1) ──────────────────────────

    /// Allocates an IVRSystem vtable (80 slots) and returns the guest object address.
    pub(crate) fn alloc_ivrsystem_vtable(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        let mut methods = vec![unsupported_method(&self.telemetry, "IVRSystem::unsupported"); 80];
        methods[0] = unsupported_method(&self.telemetry, "IVRSystem::Release");
        methods[5] = HostThunk::SteamVR_IVRSystem_GetTrackedDeviceClass;
        methods[6] = HostThunk::SteamVR_IVRSystem_IsTrackedDeviceConnected;
        methods[7] = HostThunk::SteamVR_IVRSystem_GetStringTrackedDeviceProperty;
        methods[8] = HostThunk::SteamVR_IVRSystem_GetBoolTrackedDeviceProperty;
        methods[9] = HostThunk::SteamVR_IVRSystem_GetFloatTrackedDeviceProperty;
        methods[10] = HostThunk::SteamVR_IVRSystem_GetInt32TrackedDeviceProperty;
        methods[11] = HostThunk::SteamVR_IVRSystem_GetUint64TrackedDeviceProperty;
        methods[14] = HostThunk::SteamVR_IVRSystem_GetRecommendedRenderTargetSize;
        methods[17] = HostThunk::SteamVR_IVRSystem_GetProjectionMatrix;
        methods[18] = HostThunk::SteamVR_IVRSystem_GetProjectionRaw;
        methods[19] = HostThunk::SteamVR_IVRSystem_GetEyeToHeadTransform;
        methods[22] = HostThunk::SteamVR_IVRSystem_GetDeviceToAbsoluteTrackingPose;
        methods[32] = HostThunk::SteamVR_IVRSystem_PollNextEvent;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::SteamVRHmd, vtable)?;
        Ok(object)
    }

    /// Allocates an IVRCompositor vtable (40 slots) and returns the guest object address.
    pub(crate) fn alloc_ivrcompositor_vtable(
        &mut self,
        memory: &mut MemoryImage,
    ) -> AppResult<u64> {
        let mut methods =
            vec![unsupported_method(&self.telemetry, "IVRCompositor::unsupported"); 40];
        methods[0] = unsupported_method(&self.telemetry, "IVRCompositor::Release");
        methods[5] = HostThunk::SteamVR_IVRCompositor_Submit;
        methods[6] = HostThunk::SteamVR_IVRCompositor_WaitGetPoses;
        methods[7] = HostThunk::SteamVR_IVRCompositor_GetFrameTiming;
        methods[8] = HostThunk::SteamVR_IVRCompositor_GetFrameTimeRemaining;
        methods[10] = HostThunk::SteamVR_IVRCompositor_GetCumulativeStats;
        methods[12] = HostThunk::SteamVR_IVRCompositor_CanRenderScene;
        methods[16] = HostThunk::SteamVR_IVRCompositor_SetExplicitTimingMode;
        methods[17] = HostThunk::SteamVR_IVRCompositor_SetExplicitTimingLastPose;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::SteamVRCompositor, vtable)?;
        Ok(object)
    }

    /// Allocates an IVRChaperone vtable (20 slots) and returns the guest object address.
    pub(crate) fn alloc_ivrchaperone_vtable(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        let mut methods =
            vec![unsupported_method(&self.telemetry, "IVRChaperone::unsupported"); 20];
        methods[0] = unsupported_method(&self.telemetry, "IVRChaperone::Release");
        methods[1] = HostThunk::SteamVR_IVRChaperone_GetCalibrationState;
        methods[2] = HostThunk::SteamVR_IVRChaperone_GetPlayAreaSize;
        methods[3] = HostThunk::SteamVR_IVRChaperone_GetPlayAreaRect;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::SteamVRChaperone, vtable)?;
        Ok(object)
    }

    /// Allocates an IVRController vtable (10 slots) and returns the guest object address.
    pub(crate) fn alloc_ivrcontroller_vtable(
        &mut self,
        memory: &mut MemoryImage,
    ) -> AppResult<u64> {
        let mut methods =
            vec![unsupported_method(&self.telemetry, "IVRController::unsupported"); 10];
        methods[0] = HostThunk::SteamVR_IVRController_Release;
        methods[1] = HostThunk::SteamVR_IVRController_TriggerHapticPulse;
        // Slot 2 = unused TriggerHapticPulseV2
        methods[3] = HostThunk::SteamVR_IVRController_GetControllerState;
        methods[4] = HostThunk::SteamVR_IVRController_GetControllerStateForNextFrame;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::SteamVRController, vtable)?;
        Ok(object)
    }

    /// Allocates an IVRInput vtable (20 slots) and returns the guest object address.
    pub(crate) fn alloc_ivrinput_vtable(&mut self, memory: &mut MemoryImage) -> AppResult<u64> {
        let mut methods = vec![unsupported_method(&self.telemetry, "IVRInput::unsupported"); 20];
        methods[0] = HostThunk::SteamVR_IVRInput_Release;
        methods[1] = HostThunk::SteamVR_IVRInput_SetActionManifestPath;
        methods[2] = HostThunk::SteamVR_IVRInput_GetActionHandle;
        methods[3] = HostThunk::SteamVR_IVRInput_GetActionHandle; // GetDigitalActionHandle
        methods[4] = HostThunk::SteamVR_IVRInput_GetActionHandle; // GetAnalogActionHandle
        methods[5] = HostThunk::SteamVR_IVRInput_GetActionSetHandle;
        methods[6] = HostThunk::SteamVR_IVRInput_GetDigitalActionData;
        methods[7] = HostThunk::SteamVR_IVRInput_GetAnalogActionData;
        methods[8] = HostThunk::SteamVR_IVRInput_GetActionSetHandle;
        methods[9] = HostThunk::SteamVR_IVRInput_ActivateActionSet;
        methods[10] = HostThunk::SteamVR_IVRInput_GetCurrentActionSet;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object = self.alloc_guest_object(memory, GuestObjectKind::SteamVRInput, vtable)?;
        Ok(object)
    }

    /// Allocates an IVRRenderModels vtable (30 slots) and returns the guest object address.
    pub(crate) fn alloc_ivrrender_models_vtable(
        &mut self,
        memory: &mut MemoryImage,
    ) -> AppResult<u64> {
        let mut methods =
            vec![unsupported_method(&self.telemetry, "IVRRenderModels::unsupported"); 30];
        methods[0] = unsupported_method(&self.telemetry, "IVRRenderModels::Release");
        methods[3] = HostThunk::SteamVR_IVRRenderModels_LoadRenderModel;
        methods[4] = HostThunk::SteamVR_IVRRenderModels_FreeRenderModel;
        methods[5] = HostThunk::SteamVR_IVRRenderModels_GetRenderModelName;
        methods[6] = HostThunk::SteamVR_IVRRenderModels_GetRenderModelCount;
        methods[7] = HostThunk::SteamVR_IVRRenderModels_GetRenderModelNameByIndex;
        methods[8] = HostThunk::SteamVR_IVRRenderModels_GetRenderModelThumbnail;
        methods[9] = HostThunk::SteamVR_IVRRenderModels_LoadIntoTextureD3D11;
        methods[10] = HostThunk::SteamVR_IVRRenderModels_LoadTextureD3D11_Async;
        methods[11] = HostThunk::SteamVR_IVRRenderModels_FreeTextureD3D11;
        let vtable = self.alloc_guest_vtable(memory, methods)?;
        let object =
            self.alloc_guest_object(memory, GuestObjectKind::SteamVRRenderModels, vtable)?;
        Ok(object)
    }

    // ── WebView2 COM object allocators ───────────────────────────────────────

    /// Allocate a guest object for an ICoreWebView2Environment.
    pub(crate) fn alloc_webview2_environment_object(
        &mut self,
        _env_id: u64,
        memory: &mut MemoryImage,
    ) -> u64 {
        // 3 IUnknown methods + 3 ICoreWebView2Environment methods = 6 slots
        let methods = vec![
            unsupported_method(&self.telemetry, "IUnknown::QueryInterface"), // 0
            HostThunk::GuestObjectAddRef,                                    // 1
            HostThunk::WebView2EnvRelease,                                   // 2
            HostThunk::WebView2EnvCreateCoreWebView2Controller,              // 3
            HostThunk::WebView2EnvCreateWebResourceResponse,                 // 4
            HostThunk::WebView2EnvGetBrowserVersionString,                   // 5
        ];
        let vtable = self.alloc_guest_vtable(memory, methods).unwrap_or(0);

        self.alloc_guest_object(memory, GuestObjectKind::WebView2Environment, vtable)
            .unwrap_or(0)
    }

    /// Allocate a guest object for an ICoreWebView2Controller.
    pub(crate) fn alloc_webview2_controller_object(
        &mut self,
        _ctrl_id: u64,
        memory: &mut MemoryImage,
    ) -> u64 {
        // 3 IUnknown + 7 ICoreWebView2Controller methods = 10 slots
        let methods = vec![
            unsupported_method(&self.telemetry, "IUnknown::QueryInterface"), // 0
            HostThunk::GuestObjectAddRef,                                    // 1
            HostThunk::WebView2CtrlRelease,                                  // 2
            HostThunk::WebView2CtrlGetIsVisible,                             // 3
            HostThunk::WebView2CtrlPutIsVisible,                             // 4
            HostThunk::WebView2CtrlGetBounds,                                // 5
            HostThunk::WebView2CtrlPutBounds,                                // 6
            HostThunk::WebView2CtrlGetZoomFactor,                            // 7
            HostThunk::WebView2CtrlPutZoomFactor,                            // 8
            HostThunk::WebView2CtrlMoveFocus,                                // 9
            unsupported_method(
                &self.telemetry,
                "ICoreWebView2Controller::get_IsBrowserFocusEnabled",
            ), // 10
            HostThunk::WebView2CtrlClose,                                    // 11
            HostThunk::WebView2CtrlGetCoreWebView2,                          // 12
        ];
        let vtable = self.alloc_guest_vtable(memory, methods).unwrap_or(0);

        self.alloc_guest_object(memory, GuestObjectKind::WebView2Controller, vtable)
            .unwrap_or(0)
    }

    /// Allocate a guest object for an ICoreWebView2.
    pub(crate) fn alloc_webview2_webview_object(
        &mut self,
        _webview_id: u64,
        memory: &mut MemoryImage,
    ) -> u64 {
        // 3 IUnknown + ~28 ICoreWebView2/2/3/4 methods = 31 slots
        let mut methods =
            vec![unsupported_method(&self.telemetry, "ICoreWebView2::unsupported"); 31];
        methods[0] = unsupported_method(&self.telemetry, "IUnknown::QueryInterface");
        methods[1] = HostThunk::GuestObjectAddRef;
        methods[2] = HostThunk::WebView2Release;
        methods[3] = HostThunk::WebView2GetSettings;
        methods[4] = HostThunk::WebView2GetSource;
        methods[5] = HostThunk::WebView2Navigate;
        methods[6] = HostThunk::WebView2NavigateToString;
        methods[7] = HostThunk::WebView2AddNavigationStarting;
        methods[8] = HostThunk::WebView2RemoveNavigationStarting;
        methods[9] = HostThunk::WebView2AddNavigationCompleted;
        methods[10] = HostThunk::WebView2RemoveNavigationCompleted;
        methods[11] = HostThunk::WebView2AddWebMessageReceived;
        methods[12] = HostThunk::WebView2RemoveWebMessageReceived;
        methods[13] = HostThunk::WebView2Stop;
        methods[14] = HostThunk::WebView2Reload;
        methods[15] = HostThunk::WebView2ExecuteScript;
        methods[16] = HostThunk::WebView2PostWebMessageAsJson;
        methods[17] = HostThunk::WebView2PostWebMessageAsString;
        methods[18] = HostThunk::WebView2GetSettings;
        // ICoreWebView2_2 (indices 19-24)
        methods[19] = HostThunk::WebView2AddContentLoading;
        methods[20] = HostThunk::WebView2RemoveContentLoading;
        methods[21] = HostThunk::WebView2AddSourceChanged;
        methods[22] = HostThunk::WebView2RemoveSourceChanged;
        methods[23] = HostThunk::WebView2AddHistoryChanged;
        methods[24] = HostThunk::WebView2RemoveHistoryChanged;
        // ICoreWebView2_3 (indices 25-30)
        methods[25] = HostThunk::WebView2AddNewWindowRequested;
        methods[26] = HostThunk::WebView2RemoveNewWindowRequested;
        methods[27] = HostThunk::WebView2AddPermissionRequested;
        methods[28] = HostThunk::WebView2RemovePermissionRequested;
        methods[29] = HostThunk::WebView2AddProcessFailed;
        methods[30] = HostThunk::WebView2RemoveProcessFailed;
        // ICoreWebView2_4 would follow at indices 31+
        let vtable = self.alloc_guest_vtable(memory, methods).unwrap_or(0);

        self.alloc_guest_object(memory, GuestObjectKind::WebView2WebView, vtable)
            .unwrap_or(0)
    }

    /// Allocate a guest object for an ICoreWebView2Settings.
    pub(crate) fn alloc_webview2_settings_object(&mut self, memory: &mut MemoryImage) -> u64 {
        // 3 IUnknown + 12 ICoreWebView2Settings methods = 15 slots
        let mut methods =
            vec![unsupported_method(&self.telemetry, "ICoreWebView2Settings::unsupported"); 15];
        methods[0] = unsupported_method(&self.telemetry, "IUnknown::QueryInterface");
        methods[1] = HostThunk::GuestObjectAddRef;
        methods[2] = HostThunk::WebView2SettingsRelease;
        methods[3] = HostThunk::WebView2SettingsGetIsScriptEnabled;
        methods[4] = HostThunk::WebView2SettingsPutIsScriptEnabled;
        methods[5] = HostThunk::WebView2SettingsGetIsWebMessageEnabled;
        methods[6] = HostThunk::WebView2SettingsPutIsWebMessageEnabled;
        methods[7] = HostThunk::WebView2SettingsGetAreDevToolsEnabled;
        methods[8] = HostThunk::WebView2SettingsPutAreDevToolsEnabled;
        methods[9] = HostThunk::WebView2SettingsGetIsStatusBarEnabled;
        methods[10] = HostThunk::WebView2SettingsPutIsStatusBarEnabled;
        methods[11] = HostThunk::WebView2SettingsGetDefaultBackgroundColor;
        methods[12] = HostThunk::WebView2SettingsPutDefaultBackgroundColor;
        methods[13] = HostThunk::WebView2SettingsGetIsBuiltInErrorPageEnabled;
        methods[14] = HostThunk::WebView2SettingsPutIsBuiltInErrorPageEnabled;
        let vtable = self.alloc_guest_vtable(memory, methods).unwrap_or(0);

        self.alloc_guest_object(memory, GuestObjectKind::WebView2Settings, vtable)
            .unwrap_or(0)
    }

    /// Allocate a guest object for an ICoreWebView2WebResourceResponse.
    /// Minimal implementation: 3 IUnknown + 2 property getters = 5 vtable slots.
    pub(crate) fn alloc_webview2_web_resource_response_object(
        &mut self,
        memory: &mut MemoryImage,
    ) -> u64 {
        // 3 IUnknown + GetContent + GetHeaders = 5 slots
        let methods = vec![
            unsupported_method(&self.telemetry, "IUnknown::QueryInterface"), // 0
            HostThunk::GuestObjectAddRef,                                    // 1
            HostThunk::WebView2WebResourceResponseRelease,                   // 2
            unsupported_method(
                &self.telemetry,
                "ICoreWebView2WebResourceResponse::get_Content",
            ), // 3
            unsupported_method(
                &self.telemetry,
                "ICoreWebView2WebResourceResponse::get_Headers",
            ), // 4
        ];
        let vtable = self.alloc_guest_vtable(memory, methods).unwrap_or(0);

        self.alloc_guest_object(memory, GuestObjectKind::WebView2WebResourceResponse, vtable)
            .unwrap_or(0)
    }

    /// Find the latest WebView2 environment (for CreateCoreWebView2Controller dispatch).
    /// In a real scenario we'd track the 'this' pointer, but simplified for now.
    pub(crate) fn find_webview2_env_for_controller(&self) -> u64 {
        self.webview2_runtime
            .environments
            .keys()
            .next()
            .copied()
            .unwrap_or(0)
    }

    pub(crate) fn overlapped_event_handle(
        &self,
        memory: &MemoryImage,
        overlapped: u64,
    ) -> Option<u32> {
        if overlapped == 0 {
            return None;
        }
        let h_event = if self.guest_arch == GuestArch::X64 {
            read_u64(memory, overlapped + 24).ok()? as u32
        } else {
            read_u32(memory, overlapped + 16).ok()?
        };
        (h_event != 0
            && self
                .win32
                .handle_object_type(h_event)
                .is_ok_and(|object_type| object_type == crate::win32::ObjectType::Event))
        .then_some(h_event)
    }
    pub(crate) fn create_cert_context(
        &mut self,
        memory: &mut MemoryImage,
        der_bytes: &[u8],
    ) -> AppResult<u64> {
        let ctx_size = 64 + der_bytes.len();
        let ctx_handle = self.alloc_heap(memory, ctx_size, true)?;
        write_u32(memory, ctx_handle, 0x43455254); // "CERT" magic
        write_u32(memory, ctx_handle + 4, der_bytes.len() as u32);
        for (i, &byte) in der_bytes.iter().enumerate() {
            memory.write_u8(ctx_handle + 64 + i as u64, byte);
        }
        self.cert_contexts.insert(ctx_handle, der_bytes.to_vec());
        if let Some(cert) = crate::security::Certificate::from_der(der_bytes.to_vec()) {
            let (not_before, not_after) =
                crate::security::parse_x509_validity(der_bytes).unwrap_or((0, 0));
            self.cert_parsed.insert(
                ctx_handle,
                ParsedCertificate {
                    subject: cert.subject,
                    issuer: cert.issuer,
                    serial_number: cert.serial_number,
                    thumbprint: cert.thumbprint,
                    is_root: cert.is_root,
                    not_before,
                    not_after,
                },
            );
        }
        Ok(ctx_handle)
    }
    pub(crate) fn find_issuer_certificate(
        &self,
        store_handle: u64,
        issuer: &str,
    ) -> Option<Vec<u8>> {
        let certificates: Vec<Vec<u8>> = if store_handle == 0 {
            Vec::new()
        } else {
            self.cert_store_manager
                .get_store(store_handle)
                .map(|store| {
                    store
                        .certificates
                        .iter()
                        .map(|cert| cert.der.clone())
                        .collect()
                })
                .unwrap_or_default()
        };
        certificates.into_iter().find(|der| {
            crate::security::Certificate::from_der(der.clone())
                .is_some_and(|cert| cert.subject.eq_ignore_ascii_case(issuer))
        })
    }

    pub(crate) fn module_for_resource(
        &self,
        module_handle: u64,
    ) -> AppResult<(String, Option<u64>)> {
        if module_handle == 0 || module_handle == self.mapped_image_base {
            return Ok((self.main_module_path.clone(), Some(self.mapped_image_base)));
        }
        if let Some(state) = self
            .loaded_real_dlls
            .values()
            .find(|state| state.handle == module_handle)
        {
            return Ok((state.path.display().to_string(), None));
        }
        if let Some(path) = self.module_paths_by_handle.get(&module_handle) {
            return Ok((path.clone(), None));
        }
        Err(AppError::new(
            ReasonCode::RcWin32InvalidHandle,
            format!("unknown module handle {module_handle:#x}"),
        ))
    }
}
