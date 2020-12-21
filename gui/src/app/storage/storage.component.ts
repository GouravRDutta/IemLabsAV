import { Component, OnInit } from '@angular/core';
import { Http } from '@angular/http';
import { Router} from '@angular/router';

@Component({
  selector: 'app-storage',
  templateUrl: './storage.component.html',
  styleUrls: ['./storage.component.css']
})
export class StorageComponent implements OnInit {

  apiRoot = '';
  storage = [];

  constructor(private http: Http, private router: Router) { }

  ngOnInit() {
    this.apiRoot = localStorage.getItem('endpoint');
    if (!this.apiRoot) {
      this.router.navigate(['/config']);
    }
    this.getStorage();
  }

  getStorage() {
    const geturl = `${this.apiRoot}hdd`;
    this.http.get(geturl).subscribe((res) => {
      if (res.status === 200) {
        this.storage = res.json()['data'];
      }
    });
  }
}
