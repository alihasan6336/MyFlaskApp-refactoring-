var checkedBoxs = 0;
var checkedBoxs1 = 0;

function l(id){
        var listeningId = document.querySelector(id);
        var allListening = document.querySelectorAll(".listening");

        if (listeningId.checked == true) {
                checkedBoxs++;
        } else {
                checkedBoxs--;
        }

        if (checkedBoxs == 4) {
                

                for(var i = 0; i < 10; i++) {
                        if (allListening[i].checked == false) {
                                allListening[i].disabled = true;
                        }
                }
        }else {
                for(var i = 0; i < 10; i ++) {
                        allListening[i].disabled = false;
                }
        }
}


function r(id){
        var listeningId = document.querySelector(id);
        var allListening = document.querySelectorAll(".reading");

        if (listeningId.checked == true) {
                checkedBoxs1++;
                }
                if (listeningId.checked == false) {
                        checkedBoxs1--;
        }

        if (checkedBoxs1 == 4) {
                

                for(var i = 0; i < 10; i ++) {
                        if (allListening[i].checked == false) {
                                allListening[i].disabled = true;
                        }
                }
        }else {
                for(var i = 0; i < 10; i ++) {
                        allListening[i].disabled = false;
                }
        }
}


function notR(name){
        var x = document.getElementsByName(name);
        for(var i = 0; i < x.length; i++){
                x[i].disabled = false;
        }
        for(var i = 0; i < x.length; i++){
                if(x[i].checked){
                        for(var y = 0; y < x.length; y++){
                                if(x[y] != x[i]){
                                        x[y].disabled = true;
                                }
                        }
                        break;
                }
        }
}


// Set the date we're counting down to     
var now = new Date().getTime();
var countDownDate = new Date(now + 1200000).getTime();

// Update the count down every 1 second
var x = setInterval(function() {

    // Get today's date and time
    var now = new Date().getTime();
    
    // Find the distance between now and the count down date
    var distance = countDownDate - now;
    
    var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
    var seconds = Math.floor((distance % (1000 * 60)) / 1000);
    
    try{
        document.getElementById("demo").innerHTML = minutes + " :  " + seconds;
    }catch{}

    // If the count down is over, write some text 
    if (distance < 0) {
    try{
        document.myForm.submit();
    }catch{
            window.location = "/logout";
    }
    clearInterval(x);
    }
}, 998);
